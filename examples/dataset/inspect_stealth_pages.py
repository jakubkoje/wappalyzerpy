from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from wappalyzer_pure.api import analyze_response
from wappalyzer_pure.engine import extract_html_artifacts, get_default_wappalyzer
from wappalyzer_pure.fetching import (
    FetchHeaderProfile,
    FetchOptions,
    FetchTLSMode,
    build_request_headers,
    fetch_url,
)
from wappalyzer_pure.models import AnalysisResult

READ_LIMIT = 256_000

MARKER_PATTERNS: dict[str, tuple[str, ...]] = {
    "akamai": (
        "akamai",
        "akamaighost",
        "x-akamai-",
        "_abck",
        "bm_sv",
        "bm_sz",
        "ak_bmsc",
        "akamai bot manager",
        "aka_debug",
    ),
    "perimeterx": (
        "perimeterx",
        "pxi.pub",
        "_px",
        "px-captcha",
        "human security",
    ),
    "datadome": ("datadome", "captcha-delivery.com", "ct.datadome.co"),
    "kasada": ("kasada", "kpsdk"),
    "cloudflare": ("cloudflare", "cf-ray", "__cf_bm", "turnstile"),
    "recaptcha": ("recaptcha", "google.com/recaptcha", "recaptcha.net"),
    "hcaptcha": ("hcaptcha", "cf-hcaptcha-container"),
    "geetest": ("geetest", "geetest.com"),
    "imperva": ("imperva", "incapsula", "visid_incap", "nlbi_", "incap_ses"),
    "shape": ("shape", "f5", "shape-f5"),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site", action="append", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/dataset/output/stealth_page_inspection.json"),
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    client = get_default_wappalyzer()
    options = FetchOptions(
        timeout=args.timeout,
        retries=1,
        retry_backoff_seconds=0.25,
        allow_partial_reads=True,
        tls_mode=FetchTLSMode.STRICT,
        header_profile=FetchHeaderProfile.BROWSER,
    )
    request_headers = build_request_headers(
        request_headers=None,
        user_agent=None,
        options=options,
    )

    rows: list[dict[str, object]] = []
    for raw_site in args.site:
        url = raw_site if raw_site.startswith("http") else f"https://{raw_site}"
        fetched = fetch_url(
            url,
            request_headers=request_headers,
            options=options,
            accept_http_error_response=True,
            read_limit=READ_LIMIT,
        )
        if hasattr(fetched, "category"):
            rows.append(
                {
                    "site": raw_site,
                    "url": url,
                    "fetch_failure": {
                        "category": fetched.category,
                        "error_type": fetched.error_type,
                        "message": fetched.message,
                        "attempts": fetched.attempts,
                    },
                }
            )
            continue

        analysis = analyze_response(
            fetched.headers,
            fetched.body,
            status_code=fetched.status_code,
            response_url=fetched.final_url,
            client=client,
        )
        rows.append(_build_row(raw_site, url, fetched.final_url, fetched.status_code, fetched.headers, fetched.body, analysis))

    args.output.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {args.output}")
    for row in rows:
        _print_row(row)
    return 0


def _build_row(
    site: str,
    url: str,
    final_url: str,
    status_code: int | None,
    headers: dict[str, list[str]],
    body: bytes,
    analysis: AnalysisResult,
) -> dict[str, object]:
    body_text = body.decode("latin-1", errors="replace")
    html_artifacts = extract_html_artifacts(body_text)
    normalized_headers = {key.lower(): values for key, values in headers.items()}
    header_lines = [f"{key}: {' | '.join(values)}" for key, values in normalized_headers.items()]
    header_blob = "\n".join(header_lines).lower()
    body_blob = body_text.lower()
    script_sources = list(html_artifacts.script_sources)
    script_blob = "\n".join(script_sources).lower()
    combined_blob = "\n".join([header_blob, body_blob, script_blob])

    return {
        "site": site,
        "url": url,
        "final_url": final_url,
        "status_code": status_code,
        "body_length": len(body),
        "headers_of_interest": _headers_of_interest(normalized_headers),
        "cookie_names": _cookie_names(normalized_headers.get("set-cookie", [])),
        "analysis": {
            "technologies": [tech.name for tech in analysis.technologies],
            "anti_bot_vendors": [finding.vendor for finding in analysis.anti_bot_findings],
            "anti_bot_products": [list(finding.products) for finding in analysis.anti_bot_findings],
            "behaviors": [list(finding.behaviors) for finding in analysis.anti_bot_findings],
        },
        "csp_domains": _extract_csp_domains(normalized_headers),
        "script_sources_matching_markers": _matching_scripts(script_sources),
        "marker_hits": _find_marker_hits(combined_blob, normalized_headers, body_text, script_sources),
    }


def _headers_of_interest(headers: dict[str, list[str]]) -> dict[str, list[str]]:
    interesting: dict[str, list[str]] = {}
    explicit = {
        "server",
        "content-security-policy",
        "content-security-policy-report-only",
        "location",
        "via",
        "x-cache",
        "x-cache-hits",
        "x-cdn",
        "x-served-by",
        "x-datadome",
        "x-datadome-cid",
        "x-sucuri-id",
        "akamai-grn",
        "set-cookie",
    }
    for key, values in headers.items():
        if (
            key in explicit
            or key.startswith("x-akamai-")
            or key.startswith("cf-")
            or key.startswith("x-cache")
        ):
            interesting[key] = values
    return interesting


def _cookie_names(set_cookie_values: Iterable[str]) -> list[str]:
    names: list[str] = []
    for value in set_cookie_values:
        pair = value.split(";", 1)[0].strip()
        if "=" not in pair:
            continue
        name, _, _ = pair.partition("=")
        names.append(name)
    return names


def _extract_csp_domains(headers: dict[str, list[str]]) -> list[str]:
    values = headers.get("content-security-policy", []) + headers.get(
        "content-security-policy-report-only",
        [],
    )
    domains: set[str] = set()
    for value in values:
        for match in re.findall(r"https?://([^/\s;,'\"]+)", value, flags=re.I):
            domains.add(match.lower())
    return sorted(domains)


def _matching_scripts(script_sources: list[str]) -> list[str]:
    matches: list[str] = []
    for source in script_sources:
        lowered = source.lower()
        if any(marker in lowered for markers in MARKER_PATTERNS.values() for marker in markers):
            matches.append(source)
    return matches[:20]


def _find_marker_hits(
    combined_blob: str,
    headers: dict[str, list[str]],
    body_text: str,
    script_sources: list[str],
) -> dict[str, list[dict[str, str]]]:
    hits: dict[str, list[dict[str, str]]] = {}
    header_blob = "\n".join(
        f"{key}: {' | '.join(values)}" for key, values in headers.items()
    )
    for vendor, markers in MARKER_PATTERNS.items():
        vendor_hits: list[dict[str, str]] = []
        for marker in markers:
            index = combined_blob.find(marker)
            if index < 0:
                continue
            snippet = _find_best_snippet(marker, header_blob, body_text, script_sources)
            vendor_hits.append({"marker": marker, "snippet": snippet})
        if vendor_hits:
            hits[vendor] = vendor_hits
    return hits


def _find_best_snippet(
    marker: str,
    header_blob: str,
    body_text: str,
    script_sources: list[str],
) -> str:
    lowered_marker = marker.lower()
    for source in script_sources:
        lowered = source.lower()
        index = lowered.find(lowered_marker)
        if index >= 0:
            return _snippet(source, index, len(marker))
    lowered_headers = header_blob.lower()
    header_index = lowered_headers.find(lowered_marker)
    if header_index >= 0:
        return _snippet(header_blob, header_index, len(marker))
    lowered_body = body_text.lower()
    body_index = lowered_body.find(lowered_marker)
    if body_index >= 0:
        return _snippet(body_text, body_index, len(marker))
    return marker


def _snippet(text: str, index: int, size: int) -> str:
    start = max(0, index - 80)
    end = min(len(text), index + size + 120)
    return text[start:end].replace("\n", " ")


def _print_row(row: dict[str, object]) -> None:
    print(f"\n## {row['site']}")
    if "fetch_failure" in row:
        failure = row["fetch_failure"]
        print(
            f"fetch_failure={failure['category']} {failure['error_type']}: "
            f"{failure['message']}"
        )
        return

    print(
        f"status={row['status_code']} final={row['final_url']} "
        f"body_length={row['body_length']}"
    )
    analysis = row["analysis"]
    print(
        f"detected_vendors={analysis['anti_bot_vendors']} "
        f"technologies={analysis['technologies']}"
    )
    if row["cookie_names"]:
        print(f"cookie_names={row['cookie_names']}")
    if row["csp_domains"]:
        print(f"csp_domains={row['csp_domains'][:20]}")
    if row["headers_of_interest"]:
        print("headers_of_interest:")
        for key, values in row["headers_of_interest"].items():
            print(f"  {key}: {' | '.join(values)}")
    if row["script_sources_matching_markers"]:
        print("matching_scripts:")
        for source in row["script_sources_matching_markers"][:10]:
            print(f"  {source}")
    if row["marker_hits"]:
        print("marker_hits:")
        for vendor, hits in row["marker_hits"].items():
            for hit in hits[:4]:
                print(f"  {vendor}: {hit['marker']} -> {hit['snippet']}")


if __name__ == "__main__":
    raise SystemExit(main())
