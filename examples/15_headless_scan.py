from __future__ import annotations

import argparse
import json

from wappalyzer_pure import (
    DeepHeadlessOptions,
    HeadlessOptions,
    HeadlessWaitUntil,
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    analyze_url,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a live page in a headless browser before fingerprinting it."
    )
    parser.add_argument("url", help="target URL to scan")
    parser.add_argument(
        "--wait-until",
        choices=[state.value for state in HeadlessWaitUntil],
        default=HeadlessWaitUntil.LOAD.value,
        help="navigation readiness state to wait for before collecting DOM content",
    )
    parser.add_argument(
        "--headless-timeout",
        type=float,
        default=None,
        help="override the headless navigation timeout in seconds",
    )
    parser.add_argument(
        "--post-load-delay",
        type=float,
        default=0.5,
        help="extra settle time in seconds after navigation completes",
    )
    parser.add_argument(
        "--fetch-scripts",
        action="store_true",
        help="also fetch bounded same-origin external scripts after rendering",
    )
    parser.add_argument(
        "--deep-headless",
        action="store_true",
        help=(
            "record browser-only signals such as runtime globals, iframe URLs, "
            "resource URLs, and browser cookies"
        ),
    )
    args = parser.parse_args()

    result = analyze_url(
        args.url,
        headless_options=HeadlessOptions(
            navigation_timeout=args.headless_timeout,
            wait_until=HeadlessWaitUntil(args.wait_until),
            post_load_delay_seconds=args.post_load_delay,
        ),
        script_analysis=(
            ScriptAnalysisOptions(fetch_policy=ScriptFetchPolicy.SAME_ORIGIN)
            if args.fetch_scripts
            else None
        ),
        deep_headless=DeepHeadlessOptions() if args.deep_headless else None,
    )

    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
