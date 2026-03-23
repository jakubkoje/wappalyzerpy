from __future__ import annotations

import argparse
import json

from wappalyzer_pure import ProbeOptions, probe_url


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run active multi-request probing against a live URL."
    )
    parser.add_argument("url", help="target URL to probe")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the full JSON result instead of a short summary",
    )
    args = parser.parse_args()

    result = probe_url(
        args.url,
        probe_options=ProbeOptions(
            repeat_request=True,
            follow_up_with_cookies=True,
            browser_like_request=True,
        ),
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print(f"vendors={result.vendors}")
    print(f"challenge_observed={result.challenge_observed}")
    print(f"throttled={result.throttled}")
    for observation in result.observations:
        print(
            f"- {observation.name}: status={observation.result.status_code} "
            f"ok={observation.result.ok} "
            f"redirected={observation.redirected} "
            f"challenge_observed={observation.challenge_observed} "
            f"fetch_failure={None if observation.result.fetch_failure is None else observation.result.fetch_failure.category} "
            f"vendors={[finding.vendor for finding in observation.result.anti_bot_findings]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
