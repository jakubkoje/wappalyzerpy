from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, TypeAlias, cast


Signals: TypeAlias = dict[str, list[str] | str]
EvalRow: TypeAlias = dict[str, bool | int | str]


CATEGORY_ALIASES: dict[str, set[str]] = {
    "Cloudflare": {"cloudflare"},
    "PerimeterX": {"human", "perimeterx"},
    "Datadome": {"datadome"},
    "reCaptcha": {"recaptcha"},
    "hCaptcha": {"hcaptcha"},
    "GeeTest": {"geetest"},
    "Akamai": {"akamai"},
    "Shape": {"shape", "f5"},
    "Kasada": {"kasada"},
    "Temu Slider": {"temu"},
    "Custom Antibot": set(),
}

CSP_PATTERNS: dict[str, re.Pattern[str]] = {
    category: re.compile(
        "|".join(re.escape(alias) for alias in aliases),
        re.I,
    )
    for category, aliases in CATEGORY_ALIASES.items()
    if aliases
}


def extract_all_signals(wappalyzer: dict[str, Any] | None) -> Signals:
    out: Signals = {
        "antibot_vendors": [],
        "tech_names": [],
        "header_mentions": [],
        "confidence": "",
    }
    if not isinstance(wappalyzer, dict):
        return out

    confidences: list[str] = []
    for finding in wappalyzer.get("anti_bot_findings", []):
        if not isinstance(finding, dict):
            continue
        vendor = finding.get("vendor", "")
        antibot_vendors = _signal_list(out, "antibot_vendors")
        if isinstance(vendor, str) and vendor:
            antibot_vendors.append(vendor)
        for product in _coerce_string_list(finding.get("products")):
            antibot_vendors.append(product)
        confidence = finding.get("confidence", "")
        if confidence:
            confidences.append(confidence)

    if confidences:
        rank = {"high": 3, "medium": 2, "low": 1}
        out["confidence"] = max(confidences, key=lambda value: rank.get(value, 0))

    for tech in wappalyzer.get("technologies", []):
        if not isinstance(tech, dict):
            continue
        name = tech.get("name", "")
        if isinstance(name, str) and name and name != "HSTS":
            _signal_list(out, "tech_names").append(name)

    for header in wappalyzer.get("security_headers", []) or []:
        if not isinstance(header, dict):
            continue
        value = header.get("value", "") or ""
        if not value:
            continue
        for category, pattern in CSP_PATTERNS.items():
            if pattern.search(value):
                _signal_list(out, "header_mentions").append(category)
    out["header_mentions"] = sorted(set(_signal_list(out, "header_mentions")))
    return out


def category_detected(category: str, signals: Signals) -> tuple[bool, str]:
    aliases = CATEGORY_ALIASES.get(category, set())

    if not aliases:
        if _signal_list(signals, "antibot_vendors"):
            return True, "antibot"
        if any(_is_security_tech(name) for name in _signal_list(signals, "tech_names")):
            return True, "tech"
        return False, ""

    lower_ab = {value.lower() for value in _signal_list(signals, "antibot_vendors")}
    if any(any(alias in value for value in lower_ab) for alias in aliases):
        return True, "antibot"

    lower_techs = {value.lower() for value in _signal_list(signals, "tech_names")}
    if any(any(alias in value for value in lower_techs) for alias in aliases):
        return True, "tech"

    if category in _signal_list(signals, "header_mentions"):
        return True, "header"

    return False, ""


def _is_security_tech(name: str) -> bool:
    lowered = name.lower()
    keywords = [
        "bot",
        "captcha",
        "waf",
        "firewall",
        "security",
        "protect",
        "imperva",
        "datadome",
        "akamai",
        "cloudflare",
        "kasada",
        "perimeterx",
        "human",
    ]
    return any(keyword in lowered for keyword in keywords)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sites",
        type=Path,
        default=Path("examples/dataset/stealth_bench_sites.csv"),
    )
    parser.add_argument(
        "--results-jsonl",
        type=Path,
        default=Path("examples/dataset/output/stealth_results.jsonl"),
    )
    args = parser.parse_args()

    site_rows = _load_csv(args.sites)
    results_by_source = _load_results_jsonl(args.results_jsonl)

    rows: list[EvalRow] = []
    for row in site_rows:
        source = row["source"]
        website = row["website"]
        task_id = int(row["task_id"])
        expected = row["category"]
        payload = results_by_source.get(source)
        wappalyzer = _coerce_mapping(None if payload is None else payload.get("wappalyzer"))
        signals = extract_all_signals(wappalyzer)
        matched, match_source = category_detected(expected, signals)
        fetch_ok = bool(
            isinstance(wappalyzer, dict) and wappalyzer.get("fetch_failure") is None
        )

        parts: list[str] = []
        antibot_vendors = _signal_list(signals, "antibot_vendors")
        if antibot_vendors:
            parts.append(f'ab:[{", ".join(antibot_vendors)}]')
        security_techs = [
            tech_name
            for tech_name in _signal_list(signals, "tech_names")
            if _is_security_tech(tech_name)
        ]
        if security_techs:
            parts.append(f'tech:[{", ".join(security_techs)}]')
        header_mentions = _signal_list(signals, "header_mentions")
        if header_mentions:
            parts.append(f'hdr:[{", ".join(header_mentions)}]')

        status_code = ""
        if isinstance(wappalyzer, dict) and wappalyzer.get("status_code") is not None:
            status_code = str(wappalyzer["status_code"])

        waf_detected = bool(
            not matched
            and fetch_ok
            and bool(_signal_list(signals, "antibot_vendors"))
        )

        rows.append(
            {
                "task_id": task_id,
                "website": website,
                "expected": expected,
                "detected": "  ".join(parts) if parts else "(none)",
                "confidence": str(signals["confidence"]),
                "match": matched,
                "match_source": match_source,
                "fetch_ok": fetch_ok,
                "waf_detected": waf_detected,
                "status_code": status_code,
            }
        )

    rows.sort(key=lambda row: int(row["task_id"]))
    _print_results(rows)
    return 0


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _load_results_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            payload = json.loads(line)
            source = payload.get("source")
            if isinstance(source, str):
                rows[source] = payload
    return rows


def _print_results(rows: list[EvalRow]) -> None:
    print(
        f"\n{'ID':>3}  {'Website':<28} {'Expected':<16} "
        f"{'Match':<6} {'Src':<8} {'Status':<6} Detected"
    )
    print("-" * 145)
    for row in rows:
        match = bool(row["match"])
        fetch_ok = bool(row["fetch_ok"])
        waf_detected = bool(row["waf_detected"])
        if match:
            marker = "OK"
        elif not fetch_ok:
            marker = "ERR"
        elif waf_detected:
            marker = "WAF"
        else:
            marker = "MISS"
        print(
            f"{int(row['task_id']):>3}  {str(row['website']):<28} "
            f"{str(row['expected']):<16} {marker:<6} {str(row['match_source']):<8} "
            f"{str(row['status_code']):<6} {str(row['detected'])}"
        )

    total = len(rows)
    fetched_ok = sum(1 for row in rows if row["fetch_ok"])
    matched = sum(1 for row in rows if row["match"])
    waf_only = sum(1 for row in rows if row["waf_detected"])
    true_miss = sum(1 for row in rows if not row["match"] and row["fetch_ok"] and not row["waf_detected"])
    fetch_err = sum(1 for row in rows if not row["fetch_ok"])
    by_antibot = sum(1 for row in rows if row["match_source"] == "antibot")
    by_tech = sum(1 for row in rows if row["match_source"] == "tech")
    by_header = sum(1 for row in rows if row["match_source"] == "header")

    print("\n=== Summary by Category ===")
    print(
        f"  {'Category':<20} {'Exact':<10} {'WAF layer':<12} {'via antibot':<14} "
        f"{'via tech':<12} {'via header':<12}"
    )
    print(f"  {'-' * 82}")

    grouped: dict[str, list[EvalRow]] = defaultdict(list)
    for row in rows:
        grouped[str(row["expected"])].append(row)

    for category, items in grouped.items():
        category_total = len(items)
        category_matched = sum(1 for row in items if row["match"])
        category_waf = sum(1 for row in items if row["waf_detected"])
        category_by_antibot = sum(1 for row in items if row["match_source"] == "antibot")
        category_by_tech = sum(1 for row in items if row["match_source"] == "tech")
        category_by_header = sum(1 for row in items if row["match_source"] == "header")
        print(
            f"  {category:<20} {category_matched:>2}/{category_total:<6} "
            f"{category_waf:>2} waf        "
            f"{category_by_antibot:>2} antibot    {category_by_tech:>2} tech      "
            f"{category_by_header:>2} header"
        )

    print("\n=== Overall ===")
    print(f"  Sites:              {total}")
    print(f"  Fetched OK:         {fetched_ok}/{total}")
    print(
        f"  Exact match:        {matched}/{total} "
        f"({matched / total * 100:.1f}%)  — correct vendor detected"
    )
    print(f"    via anti_bot_findings: {by_antibot}")
    print(f"    via technologies:      {by_tech}")
    print(f"    via CSP/headers:       {by_header}")
    print(
        f"  WAF layer only:     {waf_only}/{total} "
        f"({waf_only / total * 100:.1f}%)  — outer WAF detected, inner captcha not"
    )
    print(
        f"  Any protection:     {matched + waf_only}/{total} "
        f"({(matched + waf_only) / total * 100:.1f}%)  — site identified as protected"
    )
    print(
        f"  True miss:          {true_miss}/{total} "
        f"({true_miss / total * 100:.1f}%)  — fetched OK but no antibot detected at all"
    )
    print(
        f"  Fetch error:        {fetch_err}/{total}"
    )

    print("\n=== WAF-Layer Sites (outer WAF detected, inner captcha not) ===")
    for row in rows:
        if not row["waf_detected"]:
            continue
        print(
            f"  {row['website']:<28} expected={row['expected']:<16} "
            f"status={row['status_code'] or '-':<4} detected={row['detected']}"
        )

    print("\n=== True Misses (fetched OK, nothing detected) ===")
    for row in rows:
        if row["match"] or row["waf_detected"] or not row["fetch_ok"]:
            continue
        print(
            f"  {row['website']:<28} expected={row['expected']:<16} "
            f"status={row['status_code'] or '-':<4} detected={row['detected']}"
        )

    print("\n=== Fetch Errors ===")
    for row in rows:
        if row["fetch_ok"]:
            continue
        print(
            f"  {row['website']:<28} expected={row['expected']:<16} "
            f"detected={row['detected']}"
        )


def _signal_list(signals: Signals, key: str) -> list[str]:
    return cast(list[str], signals[key])


def _coerce_mapping(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return cast(dict[str, Any], value)
    return None


def _coerce_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


if __name__ == "__main__":
    raise SystemExit(main())
