from __future__ import annotations

import ssl
from urllib import request as urllib_request

from wappalyzer_pure.fetching import (
    DEFAULT_BROWSER_USER_AGENT,
    DEFAULT_LIBRARY_USER_AGENT,
    FetchHeaderProfile,
    FetchOptions,
    FetchTLSMode,
    build_opener,
    build_request_headers,
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
