from __future__ import annotations

import json
from email.message import Message
from types import TracebackType
from typing import cast
from urllib import request as urllib_request

from wappalyzer_pure import (
    ArtifactCaptureOptions,
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    analyze_response,
)


class StaticResponse:
    def __init__(self, body: bytes, url: str, headers: dict[str, str]) -> None:
        self._body = body
        self._url = url
        message = Message()
        for key, value in headers.items():
            message[key] = value
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
        body = self._responses[url]
        return StaticResponse(
            body,
            url=url,
            headers={"Content-Type": "application/javascript; charset=utf-8"},
        )


def main() -> int:
    opener = StaticOpener(
        {
            "https://example.test/static/challenge.js": (
                b"window.kpsdk = { version: '1.0.0' };"
            )
        }
    )

    result = analyze_response(
        {
            "Content-Type": "text/html; charset=utf-8",
        },
        """
        <html>
          <head>
            <script src="/static/challenge.js"></script>
          </head>
        </html>
        """,
        response_url="https://example.test/app",
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
            max_external_scripts=4,
        ),
        script_request_headers={"Referer": "https://example.test/app"},
        script_opener=cast(urllib_request.OpenerDirector, opener),
        capture_artifacts=ArtifactCaptureOptions(body_excerpt_chars=0),
    )

    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
