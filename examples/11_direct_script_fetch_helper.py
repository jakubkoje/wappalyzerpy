from __future__ import annotations

from email.message import Message
from types import TracebackType
from typing import cast
from urllib import request as urllib_request

from wappalyzer_pure import ScriptAnalysisOptions, ScriptFetchPolicy
from wappalyzer_pure.script_analysis import fetch_external_scripts


class StaticResponse:
    def __init__(self, body: bytes, url: str) -> None:
        self._body = body
        self._url = url
        message = Message()
        message["Content-Type"] = "application/javascript; charset=utf-8"
        self.headers = message

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return 200

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._body
        return self._body[:size]

    def close(self) -> None:
        return None

    def __enter__(self) -> StaticResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        del exc_type, exc, tb
        self.close()


class StaticOpener:
    def __init__(self, responses: dict[str, bytes]) -> None:
        self._responses = responses

    def open(
        self,
        request: urllib_request.Request | str,
        data: bytes | None = None,
        timeout: float | None = 10.0,
    ) -> StaticResponse:
        del data, timeout
        url = (
            request.full_url if isinstance(request, urllib_request.Request) else request
        )
        return StaticResponse(self._responses[url], url)


def main() -> int:
    opener = StaticOpener(
        {
            "https://example.test/static/a.js": b"window.alpha = true;",
            "https://example.test/static/b.js": b"window.beta = true;",
        }
    )

    fetched = fetch_external_scripts(
        page_url="https://example.test/page",
        script_sources=("/static/a.js", "/static/b.js", "https://offsite.test/c.js"),
        options=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
            max_external_scripts=8,
            max_bytes_per_script=64_000,
            max_total_script_bytes=128_000,
        ),
        timeout=5.0,
        opener=cast(urllib_request.OpenerDirector, opener),
        request_headers={"Referer": "https://example.test/page"},
    )

    print("Fetched URLs:")
    for url in fetched.urls:
        print(f"- {url}")

    print("\nFetched contents:")
    for content in fetched.contents:
        print(f"- {content}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
