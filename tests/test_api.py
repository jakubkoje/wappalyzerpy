from __future__ import annotations

import hashlib
import http.client
import json
from collections.abc import Sequence
from dataclasses import dataclass
from email.message import Message
from typing import cast
from urllib import request as urllib_request

import pytest

from wappalyzer_pure import AntiBotEvidence, ArtifactCaptureOptions, api
from wappalyzer_pure.antibot_aliases import derive_anti_bot_alias_catalog
from wappalyzer_pure.antibot_catalog import AntiBotTechnologyCatalogEntry
from wappalyzer_pure.data_sources import FingerprintDataSource
from wappalyzer_pure.engine import Wappalyzer
from wappalyzer_pure.fetching import (
    DEFAULT_BROWSER_USER_AGENT,
    FetchedResponse,
    FetchFailure,
    FetchInfo,
    FetchOptions,
)
from wappalyzer_pure.headless import (
    DeepHeadlessOptions,
    HeadlessBrowser,
    HeadlessOptions,
    HeadlessWaitUntil,
)
from wappalyzer_pure.models import BrowserSignals
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
            "Akamai": {
                "headers": {"x-akamai-transformed": ""},
                "cats": [31],
                "description": "Akamai CDN",
                "website": "https://www.akamai.com",
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
    read_exception: Exception | None = None


@dataclass(frozen=True, slots=True)
class RequestRecord:
    url: str
    headers: tuple[tuple[str, str], ...]
    timeout: float


ResponseOutcome = ResponseSpec | Exception


class FakeHTTPResponse:
    def __init__(
        self,
        *,
        url: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        status: int,
        read_exception: Exception | None = None,
    ) -> None:
        self._url = url
        self._body = body
        self._status = status
        self._read_exception = read_exception
        self._offset = 0
        self.headers = Message()
        for key, value in headers:
            self.headers.add_header(key, value)

    def __enter__(self) -> FakeHTTPResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self, amount: int | None = None) -> bytes:
        if self._read_exception is not None:
            raise self._read_exception
        if amount is None or amount < 0:
            chunk = self._body[self._offset :]
            self._offset = len(self._body)
            return chunk
        start = self._offset
        end = min(len(self._body), start + amount)
        self._offset = end
        return self._body[start:end]

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self._status


class FakeOpener:
    def __init__(
        self,
        responses: dict[str, ResponseOutcome | Sequence[ResponseOutcome]],
    ) -> None:
        self._responses = {
            url: list(spec)
            if isinstance(spec, Sequence) and not isinstance(spec, (bytes, str))
            else [spec]
            for url, spec in responses.items()
        }
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
        queue = self._responses[url]
        spec = queue.pop(0)
        if not queue:
            queue.append(spec)
        if isinstance(spec, Exception):
            raise spec
        if not isinstance(spec, ResponseSpec):
            raise TypeError(f"unsupported fake response payload: {spec!r}")
        return FakeHTTPResponse(
            url=spec.final_url or url,
            body=spec.body,
            headers=spec.headers,
            status=spec.status,
            read_exception=spec.read_exception,
        )


@dataclass(frozen=True, slots=True)
class HeadlessRequestRecord:
    url: str
    headers: tuple[tuple[str, str], ...]
    fetch_timeout: float
    navigation_timeout: float | None
    wait_until: str
    browser: str
    deep_headless_enabled: bool


class FakeHeadlessFetcher:
    def __init__(self, result: FetchedResponse | FetchFailure) -> None:
        self._result = result
        self.calls: list[HeadlessRequestRecord] = []

    def fetch_page(
        self,
        url: str,
        *,
        request_headers: dict[str, str],
        fetch_options: FetchOptions,
        headless_options: HeadlessOptions,
        deep_headless: DeepHeadlessOptions | None = None,
    ) -> FetchedResponse | FetchFailure:
        self.calls.append(
            HeadlessRequestRecord(
                url=url,
                headers=tuple(
                    (key.lower(), value) for key, value in request_headers.items()
                ),
                fetch_timeout=fetch_options.timeout,
                navigation_timeout=headless_options.navigation_timeout,
                wait_until=headless_options.wait_until.value,
                browser=headless_options.browser.value,
                deep_headless_enabled=deep_headless is not None,
            )
        )
        return self._result


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


def test_analyze_response_promotes_csp_captcha_mentions_to_antibot_findings() -> None:
    client = Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)
    client.anti_bot_catalog = {
        "recaptcha": AntiBotTechnologyCatalogEntry(
            name="reCAPTCHA",
            vendor="reCAPTCHA",
            behaviors=("captcha",),
        )
    }
    client.anti_bot_aliases = derive_anti_bot_alias_catalog(client.anti_bot_catalog)

    result = api.analyze_response(
        {
            "Content-Security-Policy": (
                "default-src 'self'; frame-src https://www.google.com/recaptcha/;"
            ),
        },
        "<html></html>",
        client=client,
    )

    assert result.technologies == ()
    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "reCAPTCHA"
    assert finding.score == 3
    assert finding.products == ("reCAPTCHA",)
    assert finding.behaviors == ("captcha",)
    assert finding.evidence == (
        AntiBotEvidence(
            source="security_header",
            indicator="content-security-policy",
            matched_value="www.google.com/recaptcha",
            artifact=(
                "content-security-policy: default-src 'self'; frame-src "
                "https://www.google.com/recaptcha/;"
            ),
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
    assert result.fetch_failure is None
    assert result.fetch_info is not None
    assert result.fetch_info.attempts == 1


def test_analyze_url_returns_structured_fetch_failure_for_timeout(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": TimeoutError("timed out"),
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
        fetch_options=FetchOptions(
            timeout=1.0,
            retries=0,
            retry_backoff_seconds=0.0,
        ),
    )

    assert result.ok is False
    assert result.fetch_info is None
    assert result.fetch_failure == FetchFailure(
        category="timeout",
        error_type="TimeoutError",
        message="timed out",
        retryable=True,
        attempts=1,
    )
    assert result.technologies == ()


def test_analyze_url_retries_transient_disconnect_and_succeeds(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": [
                http.client.RemoteDisconnected("remote end closed connection"),
                ResponseSpec(
                    body=b"<html></html>",
                    headers=(("Server", "cloudflare"),),
                    status=200,
                ),
            ]
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
        fetch_options=FetchOptions(retries=1, retry_backoff_seconds=0.0),
    )

    assert result.ok is True
    assert result.fetch_failure is None
    assert result.fetch_info is not None
    assert result.fetch_info.attempts == 2
    assert [technology.name for technology in result.technologies] == ["Cloudflare"]


def test_analyze_url_salvages_partial_read_and_marks_fetch_info(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"",
                headers=(("Server", "cloudflare"),),
                read_exception=http.client.IncompleteRead(
                    partial=b"<html>cloudflare partial body</html>",
                    expected=64,
                ),
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert result.ok is True
    assert result.fetch_info is not None
    assert result.fetch_info.partial_response is True
    assert [technology.name for technology in result.technologies] == ["Cloudflare"]


def test_analyze_url_can_disable_partial_read_salvage(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"",
                headers=(("Server", "cloudflare"),),
                read_exception=http.client.IncompleteRead(
                    partial=b"<html>partial</html>",
                    expected=32,
                ),
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
        fetch_options=FetchOptions(
            retries=0,
            retry_backoff_seconds=0.0,
            allow_partial_reads=False,
        ),
    )

    assert result.ok is False
    assert result.fetch_failure is not None
    assert result.fetch_failure.category == "incomplete_read"


def test_analyze_url_uses_browser_headers_by_default(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"<html></html>",
                headers=(("Content-Type", "text/html"),),
            )
        }
    )

    api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    headers = _headers_to_map(opener.calls[0].headers)
    assert headers["user-agent"] == DEFAULT_BROWSER_USER_AGENT
    assert "text/html" in headers["accept"]


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


def test_analyze_url_infers_akamai_from_bare_403_and_edge_headers(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"",
                headers=(
                    ("Strict-Transport-Security", "max-age=63072000"),
                    ("X-Akamai-Transformed", "9 0 pmb=mRUM,1"),
                ),
                status=403,
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert [technology.name for technology in result.technologies] == ["Akamai"]
    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "Akamai"
    assert finding.score == 4
    assert finding.confidence == "medium"
    assert any(item.source == "status_heuristic" for item in finding.evidence)
    assert any(item.source == "status_code" for item in finding.evidence)


def test_analyze_url_infers_akamai_from_403_server_header_and_generic_block_page(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=(
                    b"<html><head><style>.x{color:red}</style></head>"
                    b"<body><h1>Access Denied</h1><p>Reference #18.test</p></body></html>"
                ),
                headers=(("Server", "AkamaiNetStorage"),),
                status=403,
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert len(result.anti_bot_findings) == 1
    finding = result.anti_bot_findings[0]
    assert finding.vendor == "Akamai"
    assert any(item.source == "status_heuristic" for item in finding.evidence)


def test_analyze_url_does_not_infer_akamai_from_full_403_page(
    client: Wappalyzer,
) -> None:
    body = "<html><body>" + "".join(
        f"<p>Product support content paragraph {index}</p>" for index in range(40)
    ) + "</body></html>"
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=body.encode(),
                headers=(("Server", "AkamaiGHost"),),
                status=403,
            )
        }
    )

    result = api.analyze_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert result.anti_bot_findings == ()


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


def test_analyze_response_can_fetch_browser_discovered_script_sources(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com/assets/runtime.js": ResponseSpec(
                body=b'window.externalcms = "6.4";',
                headers=(("Content-Type", "application/javascript"),),
            )
        }
    )

    result = api.analyze_response(
        {"Content-Type": "text/html"},
        "<html><body>rendered app shell</body></html>",
        response_url="https://example.com/dashboard",
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        ),
        script_opener=cast(urllib_request.OpenerDirector, opener),
        browser_signals=BrowserSignals(
            script_sources=("/assets/runtime.js",),
        ),
        client=client,
    )

    assert [tech.display_name for tech in result.technologies] == [
        "ExternalScriptApp:6.4"
    ]
    assert opener.calls[0].url == "https://example.com/assets/runtime.js"


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


def test_analyze_url_deep_headless_implies_headless_and_captures_browser_signals(
    client: Wappalyzer,
) -> None:
    fetcher = FakeHeadlessFetcher(
        FetchedResponse(
            target_url="https://example.com",
            final_url="https://example.com/challenge",
            status_code=200,
            headers={"Content-Type": ["text/html"]},
            body=b"<html><body>challenge</body></html>",
            fetch_info=FetchInfo(
                attempts=1,
                partial_response=False,
                header_profile="browser",
                tls_mode="strict",
                transport="headless",
                browser="chromium",
                wait_until="load",
            ),
            browser_signals=BrowserSignals(
                cookie_header="pxcts=opaque; datadome=token",
                iframe_sources=("https://captcha.example.test/frame",),
                resource_urls=("https://www.google.com/recaptcha/api.js",),
                runtime_markers=("Grecaptcha", "grecaptcha"),
            ),
        )
    )

    result = api.analyze_url(
        "https://example.com",
        client=client,
        capture_artifacts=True,
        deep_headless=True,
        headless_fetcher=fetcher,
    )

    assert result.fetch_info is not None
    assert result.fetch_info.transport == "headless"
    assert fetcher.calls[0].deep_headless_enabled is True
    assert any(finding.vendor == "reCAPTCHA" for finding in result.anti_bot_findings)
    re_captcha = next(
        finding
        for finding in result.anti_bot_findings
        if finding.vendor == "reCAPTCHA"
    )
    assert any(item.source == "runtime_marker" for item in re_captcha.evidence)
    assert result.artifacts is not None
    assert result.artifacts.browser_cookie_names == ("pxcts", "datadome")
    assert result.artifacts.resource_urls == (
        "https://www.google.com/recaptcha/api.js",
    )
    assert result.artifacts.runtime_markers == ("grecaptcha",)


def test_analyze_url_can_use_headless_fetcher_for_rendered_html(
    client: Wappalyzer,
) -> None:
    fetcher = FakeHeadlessFetcher(
        FetchedResponse(
            target_url="https://example.com",
            final_url="https://example.com/app",
            status_code=200,
            headers={"Content-Type": ["text/html"]},
            body=b'<html><script>window.inlinecms = "9.1";</script></html>',
            fetch_info=FetchInfo(
                attempts=1,
                partial_response=False,
                header_profile="browser",
                tls_mode="strict",
                transport="headless",
                browser="chromium",
                wait_until="networkidle",
            ),
        )
    )

    result = api.analyze_url(
        "https://example.com",
        client=client,
        headless_options=HeadlessOptions(),
        headless_fetcher=fetcher,
    )

    assert result.final_url == "https://example.com/app"
    assert [technology.display_name for technology in result.technologies] == [
        "InlineScriptApp:9.1"
    ]
    assert result.fetch_info is not None
    assert result.fetch_info.transport == "headless"
    assert fetcher.calls[0].url == "https://example.com"
    assert _headers_to_map(fetcher.calls[0].headers)["user-agent"] == (
        DEFAULT_BROWSER_USER_AGENT
    )


def test_analyze_url_headless_fetcher_reuses_headers_for_script_fetches(
    client: Wappalyzer,
) -> None:
    opener = FakeOpener(
        {
            "https://example.com/assets/app.js": ResponseSpec(
                body=b'window.externalcms = "5.4";',
                headers=(("Content-Type", "application/javascript"),),
            )
        }
    )
    fetcher = FakeHeadlessFetcher(
        FetchedResponse(
            target_url="https://example.com",
            final_url="https://example.com/final",
            status_code=200,
            headers={"Content-Type": ["text/html"]},
            body=b'<html><script src="/assets/app.js"></script></html>',
            fetch_info=FetchInfo(
                attempts=1,
                partial_response=False,
                header_profile="browser",
                tls_mode="strict",
                transport="headless",
                browser="firefox",
                wait_until="load",
            ),
        )
    )

    result = api.analyze_url(
        "https://example.com",
        request_headers={"X-Test": "1"},
        user_agent="Agent/2.0",
        opener=cast(urllib_request.OpenerDirector, opener),
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        ),
        client=client,
        headless_options=HeadlessOptions(
            browser=HeadlessBrowser.FIREFOX,
            navigation_timeout=12.0,
            wait_until=HeadlessWaitUntil.LOAD,
            post_load_delay_seconds=0.0,
        ),
        headless_fetcher=fetcher,
    )

    assert [technology.display_name for technology in result.technologies] == [
        "ExternalScriptApp:5.4"
    ]
    headless_headers = _headers_to_map(fetcher.calls[0].headers)
    assert headless_headers["user-agent"] == "Agent/2.0"
    assert headless_headers["x-test"] == "1"
    assert fetcher.calls[0].navigation_timeout == 12.0
    assert fetcher.calls[0].wait_until == "load"
    assert fetcher.calls[0].browser == "firefox"

    script_headers = _headers_to_map(opener.calls[0].headers)
    assert script_headers["user-agent"] == "Agent/2.0"
    assert script_headers["x-test"] == "1"
    assert script_headers["referer"] == "https://example.com/final"


def test_analyze_url_returns_headless_fetch_failure(client: Wappalyzer) -> None:
    fetcher = FakeHeadlessFetcher(
        FetchFailure(
            category="timeout",
            error_type="TimeoutError",
            message="browser timed out",
            retryable=True,
            attempts=1,
        )
    )

    result = api.analyze_url(
        "https://example.com",
        client=client,
        headless_options=HeadlessOptions(),
        headless_fetcher=fetcher,
    )

    assert result.ok is False
    assert result.fetch_failure == FetchFailure(
        category="timeout",
        error_type="TimeoutError",
        message="browser timed out",
        retryable=True,
        attempts=1,
    )
    assert result.fetch_info is None
    assert result.technologies == ()


def _headers_to_map(headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    return {key: value for key, value in headers}
