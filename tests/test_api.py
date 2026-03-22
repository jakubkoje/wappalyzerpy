from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from email.message import Message
from typing import cast
from urllib import request as urllib_request

import pytest

from wappalyzer_pure import AntiBotEvidence, ArtifactCaptureOptions, api
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
            "Cloudflare Bot Management": {
                "cookies": {"__cf_bm": ""},
                "cats": [16],
                "description": "Bot management",
                "website": "https://www.cloudflare.com/products/bot-management/",
            },
            "Cloudflare Turnstile": {
                "scriptSrc": ["challenges\\.cloudflare\\.com/turnstile/v0/api\\.js"],
                "cats": [16],
                "description": "Turnstile is Cloudflare's smart CAPTCHA alternative.",
                "website": "https://www.cloudflare.com/products/turnstile/",
            },
            "Friendly Captcha": {
                "scriptSrc": ["friendlycaptcha"],
                "cats": [16],
                "description": "Friendly Captcha is a privacy-friendly CAPTCHA alternative.",
                "website": "https://friendlycaptcha.com",
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
        "16": {"name": "Security", "priority": 1},
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
    assert result.anti_bot_findings == ()
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


def test_analyze_response_reports_cloudflare_bot_management_finding(
    client: Wappalyzer,
) -> None:
    result = api.analyze_response(
        {
            "Server": "cloudflare",
            "CF-Ray": "abc123",
            "Set-Cookie": ["__cf_bm=opaque; Path=/; HttpOnly"],
        },
        "<html></html>",
        client=client,
    )

    assert [tech.name for tech in result.technologies] == [
        "Cloudflare",
        "Cloudflare Bot Management",
    ]
    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "Cloudflare"
    assert finding.score == 8
    assert finding.confidence == "high"
    assert finding.products == ("Cloudflare Bot Management",)
    assert finding.behaviors == ("bot_management",)
    assert {(item.source, item.indicator) for item in finding.evidence} >= {
        ("cookie", "__cf_bm"),
        ("header", "cf-ray"),
        ("header_value", "server"),
        ("technology", "cloudflare bot management"),
    }
    assert result.to_dict()["anti_bot_findings"] == [finding.to_dict()]


def test_analyze_response_reports_curated_vendor_without_technology_match(
    client: Wappalyzer,
) -> None:
    result = api.analyze_response(
        {
            "Set-Cookie": ["datadome=opaque; Path=/; Secure"],
        },
        "<html></html>",
        client=client,
    )

    assert result.technologies == ()
    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "DataDome"
    assert finding.score == 3
    assert finding.confidence == "medium"
    assert finding.products == ()
    assert finding.behaviors == ("captcha",)
    assert finding.evidence == (
        AntiBotEvidence(
            source="cookie",
            indicator="datadome",
            matched_value="datadome",
            artifact="datadome=opaque; Path=/; Secure",
        ),
    )


def test_analyze_response_reports_script_source_antibot_evidence(
    client: Wappalyzer,
) -> None:
    result = api.analyze_response(
        {"Server": "cloudflare"},
        """
        <html>
          <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
        </html>
        """,
        client=client,
    )

    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "Cloudflare"
    assert finding.score == 10
    assert finding.products == ("Cloudflare Turnstile",)
    assert finding.behaviors == ("captcha",)
    assert any(item.source == "script_source" for item in finding.evidence)
    assert any(item.source == "technology" for item in finding.evidence)


def test_analyze_response_derives_antibot_from_synced_technology_data(
    client: Wappalyzer,
) -> None:
    result = api.analyze_response(
        {"Content-Type": "text/html"},
        """
        <html>
          <script src="https://cdn.example.net/friendlycaptcha/widget.js"></script>
        </html>
        """,
        client=client,
    )

    assert [tech.name for tech in result.technologies] == ["Friendly Captcha"]
    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "Friendly Captcha"
    assert finding.score == 3
    assert finding.confidence == "medium"
    assert finding.products == ("Friendly Captcha",)
    assert finding.behaviors == ("captcha",)
    assert finding.evidence == (
        AntiBotEvidence(
            source="technology",
            indicator="friendly captcha",
            matched_value="Friendly Captcha",
            artifact="Friendly Captcha",
        ),
    )


def test_analyze_response_reports_fetched_script_content_antibot_evidence(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com/static/kpsdk.js": ResponseSpec(
                body=b"window.kpsdk = { version: '1.0' };",
                headers=(("Content-Type", "application/javascript"),),
            )
        }
    )

    result = api.analyze_response(
        {"Content-Type": "text/html"},
        '<script src="/static/kpsdk.js"></script>',
        response_url="https://example.com/dashboard",
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        ),
        script_opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "Kasada"
    assert finding.score == 6
    assert finding.behaviors == ("bot_management",)
    assert any(item.source == "script_content" for item in finding.evidence)


def test_analyze_response_security_only_dict_keeps_anti_bot_findings(
    client: Wappalyzer,
) -> None:
    result = api.analyze_response(
        {
            "Server": "cloudflare",
            "Set-Cookie": ["__cf_bm=opaque; Path=/; HttpOnly"],
        },
        """
        <meta name="generator" content="MetaCMS 2.4">
        """,
        client=client,
    )

    payload = result.to_dict(security_only=True)
    technologies = cast(list[dict[str, object]], payload["technologies"])
    anti_bot_findings = cast(list[dict[str, object]], payload["anti_bot_findings"])

    assert [item["name"] for item in technologies] == [
        "Cloudflare",
        "Cloudflare Bot Management",
    ]
    assert anti_bot_findings == [result.anti_bot_findings[0].to_dict()]


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


def test_analyze_url_preserves_anti_bot_findings(client: Wappalyzer) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"<html></html>",
                headers=(
                    ("Server", "cloudflare"),
                    ("CF-Ray", "trace"),
                    ("Set-Cookie", "__cf_bm=opaque; Path=/; HttpOnly"),
                ),
                status=403,
                final_url="https://example.com/checkpoint",
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert result.status_code == 403
    assert result.final_url == "https://example.com/checkpoint"
    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "Cloudflare"
    assert finding.score == 10
    assert any(item.source == "status_code" for item in finding.evidence)
    assert any(item.source == "redirect" for item in finding.evidence)


def test_analyze_response_can_capture_response_artifacts(
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
    body = (
        '<html><script src="/static/app.js"></script>'
        '<meta name="generator" content="MetaCMS 2.4"></html>'
    )

    result = api.analyze_response(
        {
            "Content-Type": "text/html",
            "Set-Cookie": ["__cf_bm=opaque; Path=/; HttpOnly"],
        },
        body,
        response_url="https://example.com/dashboard",
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        ),
        script_opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
        capture_artifacts=ArtifactCaptureOptions(
            body_excerpt_chars=24,
            captured_at_utc="2026-03-22T12:00:00Z",
        ),
    )

    assert result.artifacts is not None
    assert result.artifacts.captured_at_utc == "2026-03-22T12:00:00Z"
    assert result.artifacts.headers[0].name == "content-type"
    assert result.artifacts.set_cookie_values == ("__cf_bm=opaque; Path=/; HttpOnly",)
    assert result.artifacts.script_sources == ("/static/app.js",)
    assert result.artifacts.fetched_script_urls == (
        "https://example.com/static/app.js",
    )
    assert result.artifacts.body_sha256 == hashlib.sha256(body.encode()).hexdigest()
    assert result.artifacts.body_excerpt == body[:24]
    payload = result.to_dict()
    assert payload["artifacts"] == result.artifacts.to_dict()


def test_analyze_url_reports_multiple_antibot_behaviors_from_response(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"<html>Just a moment... /cdn-cgi/challenge-platform/</html>",
                headers=(
                    ("Server", "cloudflare"),
                    ("Set-Cookie", "__cf_bm=opaque; Path=/; HttpOnly"),
                ),
                status=403,
                final_url="https://example.com/checkpoint",
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert len(result.anti_bot_findings) == 1
    assert result.anti_bot_findings[0].behaviors == ("bot_management", "challenge")


def test_analyze_url_can_capture_artifacts_with_generated_timestamp(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"<html></html>",
                headers=(("Content-Type", "text/html"),),
                status=200,
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
        capture_artifacts=True,
    )

    assert result.artifacts is not None
    assert result.artifacts.captured_at_utc is not None
    assert result.artifacts.body_sha256 == hashlib.sha256(b"<html></html>").hexdigest()


def test_artifact_capture_options_reject_negative_excerpt_limit() -> None:
    with pytest.raises(ValueError, match="body_excerpt_chars"):
        ArtifactCaptureOptions(body_excerpt_chars=-1)


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
