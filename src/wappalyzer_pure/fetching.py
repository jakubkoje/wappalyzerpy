from __future__ import annotations

import http.client
import socket
import ssl
import time
from collections.abc import Mapping
from dataclasses import dataclass
from email.message import Message
from enum import Enum
from http.client import HTTPMessage
from urllib import error as urllib_error
from urllib import request as urllib_request

from .models import BrowserSignals, FetchFailure, FetchInfo


class FetchTLSMode(str, Enum):
    STRICT = "strict"
    INSECURE = "insecure"


class FetchHeaderProfile(str, Enum):
    LIBRARY = "library"
    BROWSER = "browser"


DEFAULT_LIBRARY_USER_AGENT = "wappalyzer-pure/0.1.0"
DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/134.0.0.0 Safari/537.36"
)
_LIBRARY_HEADER_PROFILE = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
_BROWSER_HEADER_PROFILE = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
_RETRYABLE_DNS_ERROR_CODES = {
    getattr(socket, "EAI_AGAIN", None),
}
_READ_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True, slots=True)
class FetchOptions:
    timeout: float = 10.0
    retries: int = 1
    retry_backoff_seconds: float = 0.25
    allow_partial_reads: bool = True
    tls_mode: FetchTLSMode = FetchTLSMode.STRICT
    header_profile: FetchHeaderProfile = FetchHeaderProfile.BROWSER

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.retries < 0:
            raise ValueError("retries must be zero or greater")
        if self.retry_backoff_seconds < 0:
            raise ValueError("retry_backoff_seconds must be zero or greater")


@dataclass(frozen=True, slots=True)
class FetchedResponse:
    target_url: str
    final_url: str
    status_code: int | None
    headers: dict[str, list[str]]
    body: bytes
    fetch_info: FetchInfo
    browser_signals: BrowserSignals | None = None


def build_request_headers(
    *,
    request_headers: Mapping[str, str] | None,
    user_agent: str | None,
    options: FetchOptions,
) -> dict[str, str]:
    if options.header_profile is FetchHeaderProfile.BROWSER:
        headers = dict(_BROWSER_HEADER_PROFILE)
        default_user_agent = DEFAULT_BROWSER_USER_AGENT
    else:
        headers = dict(_LIBRARY_HEADER_PROFILE)
        default_user_agent = DEFAULT_LIBRARY_USER_AGENT
    headers["User-Agent"] = user_agent or default_user_agent
    if request_headers:
        headers.update({str(key): str(value) for key, value in request_headers.items()})
    return headers


def fetch_url(
    url: str,
    *,
    request_headers: Mapping[str, str],
    options: FetchOptions,
    opener: urllib_request.OpenerDirector | None = None,
    accept_http_error_response: bool = True,
    read_limit: int | None = None,
) -> FetchedResponse | FetchFailure:
    active_opener = opener or build_opener(options)
    max_attempts = options.retries + 1

    for attempt in range(1, max_attempts + 1):
        request = urllib_request.Request(url, headers=dict(request_headers))
        response = None
        failure: FetchFailure | None = None
        attempt_timeout = options.timeout * attempt
        try:
            response = active_opener.open(request, timeout=attempt_timeout)
        except urllib_error.HTTPError as exc:
            if accept_http_error_response:
                response = exc
            else:
                failure = _classify_fetch_exception(exc, attempts=attempt)
        except Exception as exc:  # noqa: BLE001
            failure = _classify_fetch_exception(exc, attempts=attempt)

        if response is not None:
            try:
                with response:
                    body, partial_response = _read_response_body(
                        response=response,
                        allow_partial_reads=options.allow_partial_reads,
                        read_limit=read_limit,
                    )
                    return FetchedResponse(
                        target_url=url,
                        final_url=response.geturl(),
                        status_code=response.getcode(),
                        headers=headers_from_http_message(response.headers),
                        body=body,
                        fetch_info=FetchInfo(
                            attempts=attempt,
                            partial_response=partial_response,
                            header_profile=options.header_profile.value,
                            tls_mode=options.tls_mode.value,
                        ),
                    )
            except Exception as exc:  # noqa: BLE001
                failure = _classify_fetch_exception(exc, attempts=attempt)

        if failure is None:
            failure = FetchFailure(
                category="unknown",
                error_type="RuntimeError",
                message="failed to obtain an HTTP response",
                retryable=False,
                attempts=attempt,
            )

        if not failure.retryable or attempt >= max_attempts:
            return failure

        if options.retry_backoff_seconds > 0:
            time.sleep(options.retry_backoff_seconds * attempt)

    return FetchFailure(
        category="unknown",
        error_type="RuntimeError",
        message="failed to obtain an HTTP response",
        retryable=False,
        attempts=max_attempts,
    )


def build_opener(options: FetchOptions) -> urllib_request.OpenerDirector:
    if options.tls_mode is FetchTLSMode.STRICT:
        return urllib_request.build_opener()
    context = ssl._create_unverified_context()
    return urllib_request.build_opener(urllib_request.HTTPSHandler(context=context))


def headers_from_http_message(
    message: HTTPMessage | Message[str, str],
) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key, []).append(value)
    return headers


def _read_response_body(
    *,
    response: object,
    allow_partial_reads: bool,
    read_limit: int | None,
) -> tuple[bytes, bool]:
    reader = getattr(response, "read")
    limit = None if read_limit is None else read_limit + 1
    chunks: list[bytes] = []
    total = 0

    while True:
        remaining = None if limit is None else limit - total
        if remaining is not None and remaining <= 0:
            break
        chunk_size = _READ_CHUNK_SIZE if remaining is None else min(
            _READ_CHUNK_SIZE,
            remaining,
        )
        try:
            chunk = reader(chunk_size)
        except http.client.IncompleteRead as exc:
            partial = bytes(exc.partial or b"")
            if allow_partial_reads and (chunks or partial):
                if partial:
                    chunks.append(partial)
                return b"".join(chunks), True
            raise
        except (TimeoutError, socket.timeout):
            if allow_partial_reads and chunks:
                return b"".join(chunks), True
            raise

        if not chunk:
            break

        payload = bytes(chunk)
        chunks.append(payload)
        total += len(payload)

    return b"".join(chunks), False


def _classify_fetch_exception(exc: Exception, *, attempts: int) -> FetchFailure:
    if isinstance(exc, urllib_error.HTTPError):
        return FetchFailure(
            category="http_error",
            error_type=type(exc).__name__,
            message=f"{exc.code} {exc.reason}",
            retryable=False,
            attempts=attempts,
        )

    if isinstance(exc, http.client.IncompleteRead):
        return FetchFailure(
            category="incomplete_read",
            error_type=type(exc).__name__,
            message=str(exc),
            retryable=True,
            attempts=attempts,
        )

    if isinstance(exc, http.client.RemoteDisconnected):
        return FetchFailure(
            category="disconnect",
            error_type=type(exc).__name__,
            message=str(exc),
            retryable=True,
            attempts=attempts,
        )

    if isinstance(exc, (http.client.InvalidURL, ValueError)):
        return FetchFailure(
            category="invalid_url",
            error_type=type(exc).__name__,
            message=str(exc),
            retryable=False,
            attempts=attempts,
        )

    if isinstance(exc, (TimeoutError, socket.timeout)):
        return FetchFailure(
            category="timeout",
            error_type=type(exc).__name__,
            message=str(exc),
            retryable=True,
            attempts=attempts,
        )

    if isinstance(exc, ssl.SSLCertVerificationError):
        return FetchFailure(
            category="tls",
            error_type=type(exc).__name__,
            message=str(exc),
            retryable=False,
            attempts=attempts,
        )

    if isinstance(exc, ssl.SSLError):
        return FetchFailure(
            category="tls",
            error_type=type(exc).__name__,
            message=str(exc),
            retryable=False,
            attempts=attempts,
        )

    if isinstance(exc, urllib_error.URLError):
        return _classify_url_error(exc, attempts=attempts)

    if isinstance(exc, OSError):
        return FetchFailure(
            category="network",
            error_type=type(exc).__name__,
            message=str(exc),
            retryable=True,
            attempts=attempts,
        )

    return FetchFailure(
        category="unknown",
        error_type=type(exc).__name__,
        message=str(exc),
        retryable=False,
        attempts=attempts,
    )


def _classify_url_error(exc: urllib_error.URLError, *, attempts: int) -> FetchFailure:
    reason = exc.reason
    reason_message = str(reason if reason is not None else exc)

    if isinstance(reason, ssl.SSLCertVerificationError):
        return FetchFailure(
            category="tls",
            error_type=type(reason).__name__,
            message=reason_message,
            retryable=False,
            attempts=attempts,
        )

    if isinstance(reason, ssl.SSLError):
        return FetchFailure(
            category="tls",
            error_type=type(reason).__name__,
            message=reason_message,
            retryable=False,
            attempts=attempts,
        )

    if isinstance(reason, (TimeoutError, socket.timeout)):
        return FetchFailure(
            category="timeout",
            error_type=type(reason).__name__,
            message=reason_message,
            retryable=True,
            attempts=attempts,
        )

    if isinstance(reason, socket.gaierror):
        retryable = reason.errno in _RETRYABLE_DNS_ERROR_CODES or reason.errno is None
        return FetchFailure(
            category="dns",
            error_type=type(reason).__name__,
            message=reason_message,
            retryable=retryable,
            attempts=attempts,
        )

    if isinstance(reason, ConnectionRefusedError):
        return FetchFailure(
            category="network",
            error_type=type(reason).__name__,
            message=reason_message,
            retryable=True,
            attempts=attempts,
        )

    if isinstance(reason, OSError):
        return FetchFailure(
            category="network",
            error_type=type(reason).__name__,
            message=reason_message,
            retryable=True,
            attempts=attempts,
        )

    lowered_message = reason_message.casefold()
    if "timed out" in lowered_message:
        category = "timeout"
        retryable = True
    elif "certificate" in lowered_message or "ssl" in lowered_message:
        category = "tls"
        retryable = False
    elif "name or service not known" in lowered_message:
        category = "dns"
        retryable = True
    else:
        category = "network"
        retryable = True

    return FetchFailure(
        category=category,
        error_type=type(reason if reason is not None else exc).__name__,
        message=reason_message,
        retryable=retryable,
        attempts=attempts,
    )
