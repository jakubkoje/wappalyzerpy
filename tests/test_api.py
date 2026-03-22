from __future__ import annotations

import json
from dataclasses import dataclass
from email.message import Message
from typing import cast
from urllib import request as urllib_request

import pytest

from wappalyzer_pure import api
from wappalyzer_pure.data_sources import FingerprintDataSource
from wappalyzer_pure.engine import Wappalyzer
from wappalyzer_pure.script_analysis import ScriptAnalysisOptions, ScriptFetchPolicy

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
            "InlineScriptApp": {
                "scripts": ['inlinecms\\s*=\\s*"([0-9.]+)"\\;version:\\1'],
                "cats": [1],
            },
            "ExternalScriptApp": {
                "scripts": ['externalcms\\s*=\\s*"([0-9.]+)"\\;version:\\1'],
                "cats": [1],
            },
            "LimitedScriptApp": {
                "scripts": ['limitedcms\\s*=\\s*"([0-9.]+)"\\;version:\\1'],
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


@dataclass(frozen=True, slots=True)
class ResponseSpec:
    body: bytes
    headers: tuple[tuple[str, str], ...] = ()
    status: int = 200
    final_url: str | None = None


@dataclass(frozen=True, slots=True)
class RequestRecord:
    url: str
    headers: tuple[tuple[str, str], ...]
    timeout: float


class FakeHTTPResponse:
    def __init__(
        self,
        *,
        url: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        status: int,
    ) -> None:
        self._url = url
        self._body = body
        self._status = status
        self.headers = Message()
        for key, value in headers:
            self.headers.add_header(key, value)

    def __enter__(self) -> FakeHTTPResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self, amount: int | None = None) -> bytes:
        if amount is None or amount < 0:
            return self._body
        return self._body[:amount]

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self._status


class FakeOpener:
    def __init__(self, responses: dict[str, ResponseSpec]) -> None:
        self._responses = responses
        self.calls: list[RequestRecord] = []

    def open(
        self,
        request: urllib_request.Request,
        timeout: float = 10.0,
    ) -> FakeHTTPResponse:
        url = request.full_url
        self.calls.append(
            RequestRecord(
                url=url,
                headers=tuple(
                    (key.lower(), value) for key, value in request.header_items()
                ),
                timeout=timeout,
            )
        )
        spec = self._responses[url]
        return FakeHTTPResponse(
            url=spec.final_url or url,
            body=spec.body,
            headers=spec.headers,
            status=spec.status,
        )


@pytest.fixture
def client() -> Wappalyzer:
    return Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)


def test_analyze_response_detects_header_meta_and_inline_script_matches(
    client: Wappalyzer,
) -> None:
    result = api.analyze_response(
        {
            "Server": "cloudflare",
            "Content-Type": "text/html",
        },
        """
        <meta name="generator" content="MetaCMS 2.4">
        <script>window.inlinecms = "3.7";</script>
        """,
        client=client,
    )

    assert [tech.display_name for tech in result.technologies] == [
        "Cloudflare",
        "InlineScriptApp:3.7",
        "MetaCMS:2.4",
    ]
    assert result.security_technologies[0].name == "Cloudflare"


def test_normalize_headers_rejects_invalid_values() -> None:
    with pytest.raises(TypeError):
        api.normalize_headers({"Server": 123})  # type: ignore[arg-type]


def test_analyze_response_uses_selected_packaged_source() -> None:
    result = api.analyze_response(
        {"Server": "cloudflare"},
        b"",
        source=FingerprintDataSource.HTTPARCHIVE,
    )

    assert any(technology.name == "Cloudflare" for technology in result.technologies)


def test_analyze_url_keeps_http_error_response(client: Wappalyzer) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"<html></html>",
                headers=(("Strict-Transport-Security", "max-age=63072000"),),
                status=403,
                final_url="https://example.com/login",
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert result.status_code == 403
    assert result.final_url == "https://example.com/login"
    assert any(
        header.name == "Strict-Transport-Security" and header.present
        for header in result.security_headers
    )


def test_analyze_response_fetches_same_origin_external_scripts(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com/static/app.js": ResponseSpec(
                body=b'window.externalcms = "5.4";',
                headers=(("Content-Type", "application/javascript"),),
            )
        }
    )

    result = api.analyze_response(
        {"Content-Type": "text/html"},
        '<script src="/static/app.js"></script>',
        response_url="https://example.com/dashboard",
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        ),
        script_request_headers={"User-Agent": "TestAgent/1.0"},
        script_opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert [tech.display_name for tech in result.technologies] == [
        "ExternalScriptApp:5.4"
    ]
    assert opener.calls[0].url == "https://example.com/static/app.js"
    assert _headers_to_map(opener.calls[0].headers)["user-agent"] == "TestAgent/1.0"


def test_analyze_response_requires_response_url_for_external_script_fetch(
    client: Wappalyzer,
) -> None:
    with pytest.raises(ValueError, match="response_url"):
        api.analyze_response(
            {"Content-Type": "text/html"},
            '<script src="/static/app.js"></script>',
            script_analysis=ScriptAnalysisOptions(
                fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
            ),
            client=client,
        )


def test_analyze_response_blocks_off_origin_external_scripts(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://cdn.example.net/static/app.js": ResponseSpec(
                body=b'window.externalcms = "5.4";',
                headers=(("Content-Type", "application/javascript"),),
            )
        }
    )

    result = api.analyze_response(
        {"Content-Type": "text/html"},
        '<script src="https://cdn.example.net/static/app.js"></script>',
        response_url="https://example.com/dashboard",
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        ),
        script_opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert result.technologies == ()
    assert opener.calls == []


def test_analyze_response_skips_scripts_exceeding_size_limits(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com/static/large.js": ResponseSpec(
                body=b"x" * 64,
                headers=(("Content-Type", "application/javascript"),),
            ),
            "https://example.com/static/small.js": ResponseSpec(
                body=b'window.limitedcms = "1.9";',
                headers=(("Content-Type", "application/javascript"),),
            ),
        }
    )

    result = api.analyze_response(
        {"Content-Type": "text/html"},
        """
        <script src="/static/large.js"></script>
        <script src="/static/small.js"></script>
        """,
        response_url="https://example.com/dashboard",
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
            max_bytes_per_script=32,
            max_total_script_bytes=64,
        ),
        script_opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert [tech.display_name for tech in result.technologies] == [
        "LimitedScriptApp:1.9"
    ]
    assert [call.url for call in opener.calls] == [
        "https://example.com/static/large.js",
        "https://example.com/static/small.js",
    ]


def test_analyze_url_fetches_scripts_and_forwards_request_headers(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b'<script src="/assets/app.js"></script>',
                headers=(("Content-Type", "text/html"),),
                final_url="https://example.com/final",
            ),
            "https://example.com/assets/app.js": ResponseSpec(
                body=b'window.externalcms = "5.4";',
                headers=(("Content-Type", "application/javascript"),),
            ),
        }
    )

    result = api.analyze_url(
        "https://example.com",
        request_headers={"X-Test": "1"},
        user_agent="Agent/1.0",
        opener=cast(urllib_request.OpenerDirector, opener),
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        ),
        client=client,
    )

    assert result.final_url == "https://example.com/final"
    assert [tech.display_name for tech in result.technologies] == [
        "ExternalScriptApp:5.4"
    ]

    page_headers = _headers_to_map(opener.calls[0].headers)
    script_headers = _headers_to_map(opener.calls[1].headers)
    assert page_headers["user-agent"] == "Agent/1.0"
    assert page_headers["x-test"] == "1"
    assert script_headers["user-agent"] == "Agent/1.0"
    assert script_headers["x-test"] == "1"
    assert script_headers["referer"] == "https://example.com/final"


def _headers_to_map(headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    return {key: value for key, value in headers}
