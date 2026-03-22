from __future__ import annotations

import argparse
import json

from .api import analyze_url
from .data_sources import DEFAULT_FINGERPRINT_DATA_SOURCE, FingerprintDataSource
from .exceptions import WappalyzerPureError
from .models import ArtifactCaptureOptions
from .probing import ProbeOptions, probe_url
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
    scan_parser.add_argument(
        "--artifacts",
        action="store_true",
        help="include lightweight response artifacts in the JSON result",
    )
    scan_parser.add_argument(
        "--body-excerpt-chars",
        type=int,
        default=256,
        help="maximum number of body characters to retain in captured artifacts",
    )
    scan_parser.add_argument("--json", action="store_true", help="print JSON output")
    scan_parser.add_argument(
        "--security-only",
        action="store_true",
        help="only include security-relevant technologies",
    )

    probe_parser = subparsers.add_parser(
        "probe",
        help="run optional active detection probes",
    )
    probe_parser.add_argument("url")
    probe_parser.add_argument("--timeout", type=float, default=10.0)
    probe_parser.add_argument(
        "--source",
        choices=[source.value for source in FingerprintDataSource],
        default=DEFAULT_FINGERPRINT_DATA_SOURCE.value,
        help="packaged fingerprint dataset to use",
    )
    probe_parser.add_argument(
        "--fetch-scripts",
        choices=[policy.value for policy in ScriptFetchPolicy],
        default=ScriptFetchPolicy.OFF.value,
        help="fetch external JavaScript before fingerprinting",
    )
    probe_parser.add_argument(
        "--max-external-scripts",
        type=int,
        default=8,
        help="maximum number of external script files to fetch",
    )
    probe_parser.add_argument(
        "--max-bytes-per-script",
        type=int,
        default=256_000,
        help="maximum number of bytes to read from one script",
    )
    probe_parser.add_argument(
        "--max-total-script-bytes",
        type=int,
        default=1_048_576,
        help="maximum total number of script bytes to read",
    )
    probe_parser.add_argument(
        "--artifacts",
        action="store_true",
        help="include lightweight response artifacts in each probe result",
    )
    probe_parser.add_argument(
        "--body-excerpt-chars",
        type=int,
        default=256,
        help="maximum number of body characters to retain in captured artifacts",
    )
    probe_parser.add_argument(
        "--no-repeat",
        action="store_true",
        help="skip the second identical request probe",
    )
    probe_parser.add_argument(
        "--no-cookie-follow-up",
        action="store_true",
        help="skip the follow-up request that replays response cookies",
    )
    probe_parser.add_argument(
        "--no-browser-like",
        action="store_true",
        help="skip the browser-like request profile probe",
    )
    probe_parser.add_argument("--json", action="store_true", help="print JSON output")

    args = parser.parse_args(argv)

    try:
        script_analysis = ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy(args.fetch_scripts),
            max_external_scripts=args.max_external_scripts,
            max_bytes_per_script=args.max_bytes_per_script,
            max_total_script_bytes=args.max_total_script_bytes,
        )
        artifact_capture = (
            ArtifactCaptureOptions(body_excerpt_chars=args.body_excerpt_chars)
            if args.artifacts
            else None
        )
        if args.command == "scan":
            result = analyze_url(
                args.url,
                timeout=args.timeout,
                source=args.source,
                script_analysis=script_analysis,
                capture_artifacts=artifact_capture,
            )
            if args.json:
                print(
                    json.dumps(
                        result.to_dict(security_only=args.security_only),
                        indent=2,
                    )
                )
                return 0

            technologies = (
                result.security_technologies
                if args.security_only
                else result.technologies
            )
            for technology in technologies:
                print(technology.display_name)
            return 0

        else:
            result = probe_url(
                args.url,
                timeout=args.timeout,
                source=args.source,
                script_analysis=script_analysis,
                capture_artifacts=artifact_capture,
                probe_options=ProbeOptions(
                    repeat_request=not args.no_repeat,
                    follow_up_with_cookies=not args.no_cookie_follow_up,
                    browser_like_request=not args.no_browser_like,
                ),
            )
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
                return 0

            for observation in result.observations:
                vendors = ", ".join(
                    finding.vendor for finding in observation.result.anti_bot_findings
                )
                print(
                    f"{observation.name} "
                    f"status={observation.result.status_code} "
                    f"redirected={observation.redirected} "
                    f"vendors={vendors or '-'}"
                )
            return 0
    except (ValueError, WappalyzerPureError) as exc:
        parser.exit(2, f"error: {exc}\n")
    return 0
