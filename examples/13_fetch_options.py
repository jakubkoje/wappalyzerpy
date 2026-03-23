from __future__ import annotations

import argparse
import json

from wappalyzer_pure import (
    FetchHeaderProfile,
    FetchOptions,
    FetchTLSMode,
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    analyze_url,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a live URL with explicit fetch retries, header profile, and TLS mode."
    )
    parser.add_argument("url", help="target URL to scan")
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
        help="disable TLS certificate verification for research crawls",
    )
    parser.add_argument(
        "--fetch-scripts",
        action="store_true",
        help="also fetch bounded same-origin external scripts",
    )
    args = parser.parse_args()

    result = analyze_url(
        args.url,
        fetch_options=FetchOptions(
            timeout=args.timeout,
            retries=args.retries,
            retry_backoff_seconds=args.retry_backoff,
            allow_partial_reads=True,
            tls_mode=(
                FetchTLSMode.INSECURE if args.insecure_tls else FetchTLSMode.STRICT
            ),
            header_profile=FetchHeaderProfile(args.header_profile),
        ),
        script_analysis=(
            ScriptAnalysisOptions(fetch_policy=ScriptFetchPolicy.SAME_ORIGIN)
            if args.fetch_scripts
            else None
        ),
    )

    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
