from __future__ import annotations

import argparse
import json

from .api import analyze_url
from .data_sources import DEFAULT_FINGERPRINT_DATA_SOURCE, FingerprintDataSource
from .exceptions import WappalyzerPureError
from .script_analysis import ScriptAnalysisOptions, ScriptFetchPolicy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wappalyzer-pure")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="fingerprint a URL")
    scan_parser.add_argument("url")
    scan_parser.add_argument("--timeout", type=float, default=10.0)
    scan_parser.add_argument(
        "--source",
        choices=[source.value for source in FingerprintDataSource],
        default=DEFAULT_FINGERPRINT_DATA_SOURCE.value,
        help="packaged fingerprint dataset to use",
    )
    scan_parser.add_argument(
        "--fetch-scripts",
        choices=[policy.value for policy in ScriptFetchPolicy],
        default=ScriptFetchPolicy.OFF.value,
        help="fetch external JavaScript before fingerprinting",
    )
    scan_parser.add_argument(
        "--max-external-scripts",
        type=int,
        default=8,
        help="maximum number of external script files to fetch",
    )
    scan_parser.add_argument(
        "--max-bytes-per-script",
        type=int,
        default=256_000,
        help="maximum number of bytes to read from one script",
    )
    scan_parser.add_argument(
        "--max-total-script-bytes",
        type=int,
        default=1_048_576,
        help="maximum total number of script bytes to read",
    )
    scan_parser.add_argument("--json", action="store_true", help="print JSON output")
    scan_parser.add_argument(
        "--security-only",
        action="store_true",
        help="only include security-relevant technologies",
    )

    args = parser.parse_args(argv)

    try:
        script_analysis = ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy(args.fetch_scripts),
            max_external_scripts=args.max_external_scripts,
            max_bytes_per_script=args.max_bytes_per_script,
            max_total_script_bytes=args.max_total_script_bytes,
        )
        result = analyze_url(
            args.url,
            timeout=args.timeout,
            source=args.source,
            script_analysis=script_analysis,
        )
    except (ValueError, WappalyzerPureError) as exc:
        parser.exit(2, f"error: {exc}\n")

    if args.json:
        print(json.dumps(result.to_dict(security_only=args.security_only), indent=2))
        return 0

    technologies = (
        result.security_technologies if args.security_only else result.technologies
    )
    for technology in technologies:
        print(technology.display_name)
    return 0
