from __future__ import annotations

import json
from dataclasses import dataclass
from email.message import Message
from typing import cast
from urllib import request as urllib_request

from wappalyzer_pure import ArtifactCaptureOptions, ProbeOptions, probe_url
from wappalyzer_pure.engine import Wappalyzer

FINGERPRINTS_JSON = json.dumps(
    {
        "apps": {
            "Cloudflare": {
                "headers": {"server": "cloudflare"},
                "cats": [31],
            },
            "Cloudflare Bot Management": {
                "cookies": {"__cf_bm": ""},
                "cats": [16],
            },
        }
    }
)

CATEGORIES_JSON = json.dumps(
    {
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
        self.calls: list[tuple[str, tuple[tuple[str, str], ...]]] = []

    def open(
        self,
        request: urllib_request.Request,
        timeout: float = 10.0,
    ) -> FakeHTTPResponse:
        url = request.full_url
        self.calls.append(
            (
                url,
                tuple((key.lower(), value) for key, value in request.header_items()),
            )
        )
        spec = self._responses[url]
        return FakeHTTPResponse(
            url=spec.final_url or url,
            body=spec.body,
            headers=spec.headers,
            status=spec.status,
        )


def test_probe_url_runs_initial_repeat_cookie_and_browser_like_requests() -> None:
    client = Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)
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

    result = probe_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
    )

    assert [item.name for item in result.observations] == [
        "initial",
        "repeat",
        "cookie_follow_up",
        "browser_like",
    ]
    assert result.challenge_observed is True
    assert result.throttled is False
    assert result.vendors == ("Cloudflare",)
    assert result.observations[0].response_cookie_names == ("__cf_bm",)
    assert result.observations[2].request_cookie_names == ("__cf_bm",)
    browser_headers = dict(result.observations[3].request_headers)
    assert browser_headers["User-Agent"].startswith("Mozilla/5.0")


def test_probe_url_skips_optional_steps_when_disabled_or_missing_cookies() -> None:
    client = Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"<html></html>",
                headers=(("Server", "cloudflare"),),
                status=200,
            )
        }
    )

    result = probe_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
        probe_options=ProbeOptions(
            repeat_request=False,
            follow_up_with_cookies=True,
            browser_like_request=False,
        ),
    )

    assert [item.name for item in result.observations] == ["initial"]
    assert result.challenge_observed is False
    assert result.throttled is False


def test_probe_url_marks_throttled_from_http_429() -> None:
    client = Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"<html></html>",
                headers=(("Server", "cloudflare"),),
                status=429,
            )
        }
    )

    result = probe_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
        probe_options=ProbeOptions(
            repeat_request=False,
            follow_up_with_cookies=False,
            browser_like_request=False,
        ),
    )

    assert result.throttled is True
    assert result.observations[0].throttled is True


def test_probe_url_can_capture_artifacts_for_each_observation() -> None:
    client = Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)
    opener = FakeOpener(
        {
            "https://example.com": ResponseSpec(
                body=b"<html></html>",
                headers=(("Content-Type", "text/html"),),
                status=200,
            )
        }
    )

    result = probe_url(
        "https://example.com",
        opener=cast(urllib_request.OpenerDirector, opener),
        client=client,
        probe_options=ProbeOptions(
            repeat_request=False,
            follow_up_with_cookies=False,
            browser_like_request=False,
        ),
        capture_artifacts=ArtifactCaptureOptions(
            body_excerpt_chars=8,
            captured_at_utc="2026-03-22T12:00:00Z",
        ),
    )

    assert len(result.observations) == 1
    assert result.observations[0].result.artifacts is not None
    assert result.observations[0].result.artifacts.body_excerpt == "<html></"
    assert (
        result.observations[0].result.artifacts.captured_at_utc
        == "2026-03-22T12:00:00Z"
    )
