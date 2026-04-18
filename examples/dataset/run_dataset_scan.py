from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import cast

from wappalyzer_pure import (
    DeepHeadlessOptions,
    FetchHeaderProfile,
    FetchOptions,
    FetchTLSMode,
    FingerprintDataSource,
    HeadlessBrowser,
    HeadlessOptions,
    HeadlessWaitUntil,
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    analyze_url,
)

DEFAULT_INPUT = Path("examples/dataset/train_5k.csv")
DEFAULT_OUTPUT_DIR = Path("examples/dataset/output")
SUMMARY_FIELDNAMES = (
    "source",
    "ok",
    "status_code",
    "final_url",
    "body_length",
    "fetch_attempts",
    "partial_response",
    "header_profile",
    "tls_mode",
    "transport",
    "headless_browser",
    "headless_wait_until",
    "error_category",
    "error_type",
    "error_message",
    "error_retryable",
    "technology_names",
    "security_technology_names",
    "anti_bot_vendors",
    "anti_bot_products",
    "anti_bot_behaviors",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a CSV of URLs with wappalyzer-pure and save both JSONL and CSV "
            "outputs."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="input CSV with a URL column",
    )
    parser.add_argument(
        "--column",
        default="source",
        help="CSV column name containing the URL values",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="directory where result files will be written",
    )
    parser.add_argument(
        "--jsonl-name",
        default="results.jsonl",
        help="output JSONL file name inside output-dir",
    )
    parser.add_argument(
        "--csv-name",
        default="results.csv",
        help="output CSV file name inside output-dir",
    )
    parser.add_argument("--limit", type=int, help="optional maximum number of rows")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--retry-backoff", type=float, default=0.25)
    parser.add_argument(
        "--header-profile",
        choices=[profile.value for profile in FetchHeaderProfile],
        default=FetchHeaderProfile.BROWSER.value,
    )
    parser.add_argument(
        "--insecure-tls",
        action="store_true",
        help="disable TLS verification for the page fetches",
    )
    parser.add_argument(
        "--no-partial-reads",
        action="store_true",
        help="treat incomplete response bodies as hard failures",
    )
    parser.add_argument(
        "--fetch-scripts",
        choices=[policy.value for policy in ScriptFetchPolicy],
        default=ScriptFetchPolicy.OFF.value,
        help="optional external script fetch mode",
    )
    parser.add_argument("--max-external-scripts", type=int, default=8)
    parser.add_argument("--max-bytes-per-script", type=int, default=256_000)
    parser.add_argument("--max-total-script-bytes", type=int, default=1_048_576)
    parser.add_argument(
        "--source",
        choices=[source.value for source in FingerprintDataSource],
        default=FingerprintDataSource.MERGED.value,
        help="packaged fingerprint dataset to use",
    )
    parser.add_argument(
        "--security-only",
        action="store_true",
        help="store only security-relevant technologies in the JSONL payload",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="render each page in a headless browser before fingerprinting",
    )
    parser.add_argument(
        "--deep-headless",
        action="store_true",
        help=(
            "record browser-only signals such as runtime globals, iframe URLs, "
            "resource URLs, and browser cookies; implies --headless"
        ),
    )
    parser.add_argument(
        "--headless-browser",
        choices=[browser.value for browser in HeadlessBrowser],
        default=HeadlessBrowser.CHROMIUM.value,
        help="browser engine to use when --headless is enabled",
    )
    parser.add_argument(
        "--headless-timeout",
        type=float,
        default=None,
        help="override the headless navigation timeout in seconds",
    )
    parser.add_argument(
        "--headless-wait-until",
        choices=[state.value for state in HeadlessWaitUntil],
        default=HeadlessWaitUntil.LOAD.value,
        help="navigation readiness state to wait for in headless mode",
    )
    parser.add_argument(
        "--headless-post-load-delay",
        type=float,
        default=0.5,
        help="extra settle time in seconds after the headless page load finishes",
    )
    parser.add_argument(
        "--headless-simulate-interaction",
        action="store_true",
        help="scroll the page after load to trigger lazy-loaded widgets (e.g. GeeTest)",
    )
    args = parser.parse_args()

    urls = _load_urls(args.input, column=args.column, limit=args.limit)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = args.output_dir / args.jsonl_name
    csv_path = args.output_dir / args.csv_name

    fetch_options = FetchOptions(
        timeout=args.timeout,
        retries=args.retries,
        retry_backoff_seconds=args.retry_backoff,
        allow_partial_reads=not args.no_partial_reads,
        tls_mode=FetchTLSMode.INSECURE if args.insecure_tls else FetchTLSMode.STRICT,
        header_profile=FetchHeaderProfile(args.header_profile),
    )
    script_analysis = ScriptAnalysisOptions(
        fetch_policy=ScriptFetchPolicy(args.fetch_scripts),
        max_external_scripts=args.max_external_scripts,
        max_bytes_per_script=args.max_bytes_per_script,
        max_total_script_bytes=args.max_total_script_bytes,
    )
    headless_options = (
        HeadlessOptions(
            browser=HeadlessBrowser(args.headless_browser),
            navigation_timeout=args.headless_timeout,
            wait_until=HeadlessWaitUntil(args.headless_wait_until),
            post_load_delay_seconds=args.headless_post_load_delay,
            simulate_interaction=args.headless_simulate_interaction,
        )
        if args.headless or args.deep_headless
        else None
    )
    deep_headless = DeepHeadlessOptions() if args.deep_headless else None

    ok_count = 0
    with (
        jsonl_path.open("w", encoding="utf-8") as jsonl_file,
        csv_path.open("w", encoding="utf-8", newline="") as csv_file,
        ThreadPoolExecutor(max_workers=args.workers) as executor,
    ):
        writer = csv.DictWriter(csv_file, fieldnames=SUMMARY_FIELDNAMES)
        writer.writeheader()
        scanner = partial(
            _scan_url,
            source=args.source,
            fetch_options=fetch_options,
            script_analysis=script_analysis,
            security_only=args.security_only,
            headless_options=headless_options,
            deep_headless=deep_headless,
        )

        for index, (json_record, csv_record) in enumerate(
            executor.map(scanner, urls),
            start=1,
        ):
            jsonl_file.write(json.dumps(json_record, ensure_ascii=False) + "\n")
            writer.writerow(csv_record)
            if csv_record["ok"] == "true":
                ok_count += 1
            if index % 100 == 0 or index == len(urls):
                print(
                    f"processed={index}/{len(urls)} ok={ok_count} "
                    f"failed={index - ok_count}"
                )

    print(f"jsonl={jsonl_path}")
    print(f"csv={csv_path}")
    return 0


def _load_urls(path: Path, *, column: str, limit: int | None) -> list[str]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or column not in reader.fieldnames:
            raise ValueError(
                f"input CSV does not contain column {column!r}: {reader.fieldnames!r}"
            )
        urls: list[str] = []
        for row in reader:
            raw_url = row.get(column, "")
            url = raw_url.strip()
            if not url:
                continue
            urls.append(url)
            if limit is not None and len(urls) >= limit:
                break
    return urls


def _scan_url(
    url: str,
    *,
    source: str,
    fetch_options: FetchOptions,
    script_analysis: ScriptAnalysisOptions,
    security_only: bool,
    headless_options: HeadlessOptions | None,
    deep_headless: DeepHeadlessOptions | None,
) -> tuple[dict[str, object], dict[str, str]]:
    try:
        result = analyze_url(
            url,
            source=source,
            fetch_options=fetch_options,
            script_analysis=script_analysis,
            headless_options=headless_options,
            deep_headless=deep_headless,
        )
        payload: dict[str, object] = {
            "source": url,
            "wappalyzer": result.to_dict(security_only=security_only),
        }
        return payload, _flatten_result(url, payload["wappalyzer"])
    except Exception as exc:  # noqa: BLE001
        failure_payload: dict[str, object] = {
            "target_url": url,
            "final_url": None,
            "status_code": None,
            "body_length": 0,
            "technologies": [],
            "anti_bot_findings": [],
            "security_headers": [],
            "artifacts": None,
            "fetch_info": None,
            "fetch_failure": {
                "category": "unhandled_exception",
                "error_type": type(exc).__name__,
                "message": str(exc),
                "retryable": False,
                "attempts": 1,
            },
        }
        payload: dict[str, object] = {
            "source": url,
            "wappalyzer": failure_payload,
        }
        return payload, _flatten_result(url, failure_payload)


def _flatten_result(url: str, payload: dict[str, object]) -> dict[str, str]:
    technologies = _coerce_mapping_list(payload.get("technologies"))
    anti_bot_findings = _coerce_mapping_list(payload.get("anti_bot_findings"))
    fetch_info = _coerce_mapping(payload.get("fetch_info"))
    fetch_failure = _coerce_mapping(payload.get("fetch_failure"))

    return {
        "source": url,
        "ok": "true" if fetch_failure is None else "false",
        "status_code": _stringify_scalar(payload.get("status_code")),
        "final_url": _stringify_scalar(payload.get("final_url")),
        "body_length": _stringify_scalar(payload.get("body_length")),
        "fetch_attempts": _stringify_scalar(
            None if fetch_info is None else fetch_info.get("attempts")
        ),
        "partial_response": _stringify_scalar(
            None if fetch_info is None else fetch_info.get("partial_response")
        ),
        "header_profile": _stringify_scalar(
            None if fetch_info is None else fetch_info.get("header_profile")
        ),
        "tls_mode": _stringify_scalar(
            None if fetch_info is None else fetch_info.get("tls_mode")
        ),
        "transport": _stringify_scalar(
            None if fetch_info is None else fetch_info.get("transport")
        ),
        "headless_browser": _stringify_scalar(
            None if fetch_info is None else fetch_info.get("browser")
        ),
        "headless_wait_until": _stringify_scalar(
            None if fetch_info is None else fetch_info.get("wait_until")
        ),
        "error_category": _stringify_scalar(
            None if fetch_failure is None else fetch_failure.get("category")
        ),
        "error_type": _stringify_scalar(
            None if fetch_failure is None else fetch_failure.get("error_type")
        ),
        "error_message": _stringify_scalar(
            None if fetch_failure is None else fetch_failure.get("message")
        ),
        "error_retryable": _stringify_scalar(
            None if fetch_failure is None else fetch_failure.get("retryable")
        ),
        "technology_names": _join_values(
            _stringify_scalar(item.get("display_name")) for item in technologies
        ),
        "security_technology_names": _join_values(
            _stringify_scalar(item.get("display_name"))
            for item in technologies
            if item.get("security_relevant") is True
        ),
        "anti_bot_vendors": _join_values(
            _stringify_scalar(item.get("vendor")) for item in anti_bot_findings
        ),
        "anti_bot_products": _join_values(
            _stringify_scalar(product)
            for item in anti_bot_findings
            for product in _coerce_string_list(item.get("products"))
        ),
        "anti_bot_behaviors": _join_values(
            _stringify_scalar(behavior)
            for item in anti_bot_findings
            for behavior in _coerce_string_list(item.get("behaviors"))
        ),
    }


def _coerce_mapping(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TypeError(f"expected mapping payload, got {type(value)!r}")
    return cast(dict[str, object], value)


def _coerce_mapping_list(value: object) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(f"expected list payload, got {type(value)!r}")
    items: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            raise TypeError(f"expected mapping item, got {type(item)!r}")
        items.append(cast(dict[str, object], item))
    return items


def _coerce_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(f"expected string list payload, got {type(value)!r}")
    items: list[str] = []
    for item in value:
        items.append(_stringify_scalar(item))
    return items


def _join_values(values: Iterable[str]) -> str:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return "|".join(unique)


def _stringify_scalar(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


if __name__ == "__main__":
    raise SystemExit(main())
