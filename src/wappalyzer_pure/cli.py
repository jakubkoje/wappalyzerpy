from __future__ import annotations

import argparse
import json

from .api import analyze_url
from .exceptions import WappalyzerPureError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wappalyzer-pure")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="fingerprint a URL")
    scan_parser.add_argument("url")
    scan_parser.add_argument("--timeout", type=float, default=10.0)
    scan_parser.add_argument("--json", action="store_true", help="print JSON output")
    scan_parser.add_argument(
        "--security-only",
        action="store_true",
        help="only include security-relevant technologies",
    )

    args = parser.parse_args(argv)

    try:
        result = analyze_url(args.url, timeout=args.timeout)
    except WappalyzerPureError as exc:
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
