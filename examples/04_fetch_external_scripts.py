from __future__ import annotations

import argparse
import json

from wappalyzer_pure import (
    ArtifactCaptureOptions,
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    analyze_url,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a live URL and allow bounded same-origin external script fetching."
    )
    parser.add_argument("url", help="target URL to scan")
    args = parser.parse_args()

    result = analyze_url(
        args.url,
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
            max_external_scripts=8,
            max_bytes_per_script=256_000,
            max_total_script_bytes=1_048_576,
        ),
        capture_artifacts=ArtifactCaptureOptions(body_excerpt_chars=0),
    )

    payload = result.to_dict()
    print(json.dumps(payload, indent=2))
    if result.artifacts is not None:
        print("\nFetched external script URLs:")
        for script_url in result.artifacts.fetched_script_urls:
            print(f"- {script_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
