from __future__ import annotations

import json
from typing import cast
from urllib import request as urllib_request

import pytest

from wappalyzer_pure import api
from wappalyzer_pure.engine import Wappalyzer

FINGERPRINTS_JSON = json.dumps(
    {
        "apps": {
            "Cloudflare": {
                "headers": {"server": "cloudflare"},
                "cats": [31],
                "description": "Reverse proxy and CDN",
                "website": "https://www.cloudflare.com",
            },
            "MetaCMS": {
                "meta": {"generator": ["metacms ([0-9.]+)\\;version:\\1"]},
                "cats": [1],
            },
        }
    }
)

CATEGORIES_JSON = json.dumps(
    {
        "1": {"name": "CMS", "priority": 1},
        "31": {"name": "CDN", "priority": 1},
    }
)


@pytest.fixture
def client() -> Wappalyzer:
    return Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)


def test_analyze_response_detects_header_and_meta_matches(client: Wappalyzer) -> None:
    result = api.analyze_response(
        {
            "Server": "cloudflare",
            "Content-Type": "text/html",
        },
        '<meta name="generator" content="MetaCMS 2.4">',
        client=client,
    )

    assert [tech.display_name for tech in result.technologies] == [
        "Cloudflare",
        "MetaCMS:2.4",
    ]
    assert result.security_technologies[0].name == "Cloudflare"


def test_normalize_headers_rejects_invalid_values() -> None:
    with pytest.raises(TypeError):
        api.normalize_headers({"Server": 123})  # type: ignore[arg-type]


def test_analyze_url_keeps_http_error_response(client: Wappalyzer) -> None:
    class FakeHTTPResponse:
        def __init__(self) -> None:
            from email.message import Message

            self.headers = Message()
            self.headers.add_header("Strict-Transport-Security", "max-age=63072000")

        def __enter__(self) -> FakeHTTPResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def read(self) -> bytes:
            return b"<html></html>"

        def geturl(self) -> str:
            return "https://example.com/login"

        def getcode(self) -> int:
            return 403

    class FakeOpener:
        def open(self, request, timeout=10.0):
            return FakeHTTPResponse()

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, FakeOpener()),
        client=client,
    )

    assert result.status_code == 403
    assert result.final_url == "https://example.com/login"
    assert any(
        header.name == "Strict-Transport-Security" and header.present
        for header in result.security_headers
    )
