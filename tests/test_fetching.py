from __future__ import annotations

import ssl
import socket
from dataclasses import dataclass
from urllib import request as urllib_request

from wappalyzer_pure.fetching import (
    DEFAULT_BROWSER_USER_AGENT,
    DEFAULT_LIBRARY_USER_AGENT,
    FetchHeaderProfile,
    FetchOptions,
    FetchTLSMode,
    _read_response_body,
    build_opener,
    build_request_headers,
    fetch_url,
)


def test_build_request_headers_uses_library_defaults() -> None:
    headers = build_request_headers(
        request_headers=None,
        user_agent=None,
        options=FetchOptions(header_profile=FetchHeaderProfile.LIBRARY),
    )

    assert headers["User-Agent"] == DEFAULT_LIBRARY_USER_AGENT
    assert "text/html" in headers["Accept"]


def test_build_request_headers_uses_browser_defaults() -> None:
    headers = build_request_headers(
        request_headers=None,
        user_agent=None,
        options=FetchOptions(header_profile=FetchHeaderProfile.BROWSER),
    )

    assert headers["User-Agent"] == DEFAULT_BROWSER_USER_AGENT
    assert headers["Upgrade-Insecure-Requests"] == "1"


def test_build_opener_uses_unverified_context_for_insecure_tls() -> None:
    opener = build_opener(FetchOptions(tls_mode=FetchTLSMode.INSECURE))

    handler = next(
        item
        for item in getattr(opener, "handlers")
        if isinstance(item, urllib_request.HTTPSHandler)
    )
    context = handler._context
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


class _ChunkedTimeoutResponse:
    def __init__(self, chunks: list[bytes], exc: Exception | None = None) -> None:
        self._chunks = list(chunks)
        self._exc = exc

    def read(self, amount: int | None = None) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        if self._exc is not None:
            raise self._exc
        return b""


@dataclass(frozen=True, slots=True)
class _FetchedSpec:
    body: bytes
    status: int = 200
    final_url: str = "https://example.com"


class _HTTPResponse:
    def __init__(self, spec: _FetchedSpec) -> None:
        self._spec = spec
        self.headers = {}
        self._offset = 0

    def __enter__(self) -> _HTTPResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self, amount: int | None = None) -> bytes:
        body = self._spec.body
        if amount is None or amount < 0:
            chunk = body[self._offset :]
            self._offset = len(body)
            return chunk
        start = self._offset
        end = min(len(body), start + amount)
        self._offset = end
        return body[start:end]

    def geturl(self) -> str:
        return self._spec.final_url

    def getcode(self) -> int:
        return self._spec.status


class _RetryingOpener:
    def __init__(self, outcomes: list[Exception | _FetchedSpec]) -> None:
        self._outcomes = list(outcomes)
        self.timeouts: list[float] = []

    def open(
        self,
        request: urllib_request.Request,
        timeout: float = 10.0,
    ) -> _HTTPResponse:
        self.timeouts.append(timeout)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return _HTTPResponse(outcome)


def test_read_response_body_salvages_partial_payload_on_timeout() -> None:
    body, partial = _read_response_body(
        response=_ChunkedTimeoutResponse(
            [b"hello ", b"world"],
            exc=TimeoutError("timed out"),
        ),
        allow_partial_reads=True,
        read_limit=None,
    )

    assert body == b"hello world"
    assert partial is True


def test_read_response_body_salvages_partial_payload_on_socket_timeout() -> None:
    body, partial = _read_response_body(
        response=_ChunkedTimeoutResponse(
            [b"abc"],
            exc=socket.timeout("timed out"),
        ),
        allow_partial_reads=True,
        read_limit=None,
    )

    assert body == b"abc"
    assert partial is True


def test_fetch_url_increases_timeout_budget_on_retry() -> None:
    opener = _RetryingOpener(
        [
            TimeoutError("timed out"),
            _FetchedSpec(body=b"ok"),
        ]
    )

    result = fetch_url(
        "https://example.com",
        request_headers={"User-Agent": "Test/1.0"},
        options=FetchOptions(timeout=1.0, retries=1, retry_backoff_seconds=0.0),
        opener=opener,  # type: ignore[arg-type]
    )

    assert opener.timeouts == [1.0, 2.0]
    assert result.body == b"ok"  # type: ignore[union-attr]
