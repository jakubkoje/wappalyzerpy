from __future__ import annotations

import argparse
import json

from wappalyzer_pure import analyze_url


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a live URL with the default packaged dataset."
    )
    parser.add_argument("url", help="target URL to scan")
    parser.add_argument(
        "--security-only",
        action="store_true",
        help="only include security-relevant technologies in the JSON output",
    )
    args = parser.parse_args()

    result = analyze_url(args.url)
    print(json.dumps(result.to_dict(security_only=args.security_only), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
