from __future__ import annotations

import json
from urllib import request as urllib_request

from wappalyzer_pure import FetchOptions, analyze_url


class TimeoutOpener:
    def open(
        self,
        request: urllib_request.Request,
        timeout: float = 10.0,
    ) -> object:
        raise TimeoutError(f"timed out after {timeout} seconds")


def main() -> int:
    result = analyze_url(
        "https://example.com",
        opener=TimeoutOpener(),  # type: ignore[arg-type]
        fetch_options=FetchOptions(
            timeout=1.0,
            retries=0,
            retry_backoff_seconds=0.0,
        ),
    )

    print(f"ok={result.ok}")
    print(f"fetch_failure={result.fetch_failure}")
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
