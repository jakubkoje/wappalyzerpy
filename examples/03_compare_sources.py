from __future__ import annotations

import argparse

from wappalyzer_pure import FingerprintDataSource, analyze_url


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare the packaged fingerprint sources on one live target."
    )
    parser.add_argument("url", help="target URL to scan")
    args = parser.parse_args()

    for source in FingerprintDataSource:
        result = analyze_url(args.url, source=source)
        technology_names = [
            technology.display_name for technology in result.technologies
        ]
        anti_bot_vendors = [finding.vendor for finding in result.anti_bot_findings]

        print(f"\n[{source.value}]")
        print(f"status={result.status_code} final_url={result.final_url}")
        print(f"technologies={technology_names}")
        print(f"anti_bot_vendors={anti_bot_vendors}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
