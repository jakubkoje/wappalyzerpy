from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from wappalyzer_pure import (
    DeepHeadlessOptions,
    FetchOptions,
    HeadlessOptions,
    HeadlessWaitUntil,
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    analyze_url,
)
from wappalyzer_pure.engine import Wappalyzer

pytestmark = pytest.mark.headless_integration

FINGERPRINTS_JSON = json.dumps(
    {
        "apps": {
            "RenderedMetaCMS": {
                "meta": {"generator": ["renderedmeta ([0-9.]+)\\;version:\\1"]},
                "cats": [1],
            },
            "RenderedScriptApp": {
                "scripts": ['renderedscript\\s*=\\s*"([0-9.]+)"\\;version:\\1'],
                "cats": [1],
            },
        }
    }
)

CATEGORIES_JSON = json.dumps(
    {
        "1": {"name": "CMS", "priority": 1},
    }
)


@dataclass(frozen=True, slots=True)
class LoggedRequest:
    path: str
    headers: dict[str, str]


@dataclass(slots=True)
class LiveServerState:
    base_url: str
    requests: list[LoggedRequest]
    lock: threading.Lock

    def record_request(self, path: str, headers: dict[str, str]) -> None:
        with self.lock:
            self.requests.append(LoggedRequest(path=path, headers=headers))

    def requests_for_path(self, path: str) -> list[LoggedRequest]:
        with self.lock:
            return [item for item in self.requests if item.path == path]


@pytest.fixture(scope="session")
def live_headless_browser_available() -> None:
    playwright_sync_api = pytest.importorskip("playwright.sync_api")
    try:
        with playwright_sync_api.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Chromium is not available for real headless tests: {exc}")


@pytest.fixture
def client() -> Wappalyzer:
    return Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)


@pytest.fixture
def live_server() -> Iterator[LiveServerState]:
    state = LiveServerState(
        base_url="",
        requests=[],
        lock=threading.Lock(),
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            state.record_request(
                path=path,
                headers={key.casefold(): value for key, value in self.headers.items()},
            )

            if path == "/dynamic-meta":
                body = """
                <html>
                  <head>
                    <script>
                      window.setTimeout(function () {
                        document.head.insertAdjacentHTML(
                          'beforeend',
                          '<meta name="generator" content="RenderedMeta 4.8">'
                        );
                      }, 25);
                    </script>
                  </head>
                  <body>dynamic meta</body>
                </html>
                """
                self._write_response(
                    status=HTTPStatus.OK,
                    content_type="text/html; charset=utf-8",
                    body=body.encode("utf-8"),
                )
                return

            if path == "/dynamic-script":
                body = """
                <html>
                  <head>
                    <script>
                      window.setTimeout(function () {
                        const script = document.createElement('script');
                        script.src = '/assets/rendered.js';
                        document.body.appendChild(script);
                      }, 25);
                    </script>
                  </head>
                  <body>dynamic script</body>
                </html>
                """
                self._write_response(
                    status=HTTPStatus.OK,
                    content_type="text/html; charset=utf-8",
                    body=body.encode("utf-8"),
                )
                return

            if path == "/deep-runtime":
                body = """
                <html>
                  <head>
                    <script>
                      window.setTimeout(function () {
                        const name = window.atob('Z3JlY2FwdGNoYQ==');
                        window[name] = {
                          render: function () {
                            return true;
                          }
                        };
                      }, 25);
                    </script>
                  </head>
                  <body>deep runtime</body>
                </html>
                """
                self._write_response(
                    status=HTTPStatus.OK,
                    content_type="text/html; charset=utf-8",
                    body=body.encode("utf-8"),
                )
                return

            if path == "/assets/rendered.js":
                self._write_response(
                    status=HTTPStatus.OK,
                    content_type="application/javascript; charset=utf-8",
                    body=b'window.renderedscript = "7.2";',
                )
                return

            if path == "/slow-page":
                time.sleep(0.5)
                self._write_response(
                    status=HTTPStatus.OK,
                    content_type="text/html; charset=utf-8",
                    body=b"<html><body>slow page</body></html>",
                )
                return

            self.send_error(HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return None

        def _write_response(
            self,
            *,
            status: HTTPStatus,
            content_type: str,
            body: bytes,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.base_url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_headless_analyze_url_detects_javascript_rendered_meta(
    live_headless_browser_available: None,
    live_server: LiveServerState,
    client: Wappalyzer,
) -> None:
    non_headless = analyze_url(
        f"{live_server.base_url}/dynamic-meta",
        client=client,
        fetch_options=FetchOptions(timeout=5.0, retries=0),
    )
    headless = analyze_url(
        f"{live_server.base_url}/dynamic-meta",
        client=client,
        fetch_options=FetchOptions(timeout=5.0, retries=0),
        headless_options=HeadlessOptions(
            wait_until=HeadlessWaitUntil.LOAD,
            post_load_delay_seconds=0.1,
        ),
    )

    assert non_headless.technologies == ()
    assert [technology.display_name for technology in headless.technologies] == [
        "RenderedMetaCMS:4.8"
    ]
    assert headless.fetch_info is not None
    assert headless.fetch_info.transport == "headless"
    assert headless.fetch_info.browser == "chromium"
    assert headless.fetch_info.wait_until == "load"


def test_headless_analyze_url_forwards_headers_and_fetches_rendered_scripts(
    live_headless_browser_available: None,
    live_server: LiveServerState,
    client: Wappalyzer,
) -> None:
    result = analyze_url(
        f"{live_server.base_url}/dynamic-script",
        request_headers={"X-Test": "1"},
        user_agent="Agent/2.0",
        client=client,
        fetch_options=FetchOptions(timeout=5.0, retries=0),
        script_analysis=ScriptAnalysisOptions(
            fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        ),
        headless_options=HeadlessOptions(
            wait_until=HeadlessWaitUntil.LOAD,
            post_load_delay_seconds=0.1,
        ),
    )

    assert [technology.display_name for technology in result.technologies] == [
        "RenderedScriptApp:7.2"
    ]
    assert result.fetch_info is not None
    assert result.fetch_info.transport == "headless"

    page_requests = live_server.requests_for_path("/dynamic-script")
    assert any(
        item.headers.get("user-agent") == "Agent/2.0"
        and item.headers.get("x-test") == "1"
        for item in page_requests
    )

    script_requests = live_server.requests_for_path("/assets/rendered.js")
    assert any(
        item.headers.get("user-agent") == "Agent/2.0"
        and item.headers.get("x-test") == "1"
        and item.headers.get("referer") == f"{live_server.base_url}/dynamic-script"
        and "sec-fetch-dest" not in item.headers
        for item in script_requests
    )


def test_headless_analyze_url_returns_structured_timeout_failure(
    live_headless_browser_available: None,
    live_server: LiveServerState,
    client: Wappalyzer,
) -> None:
    result = analyze_url(
        f"{live_server.base_url}/slow-page",
        client=client,
        fetch_options=FetchOptions(timeout=0.1, retries=0),
        headless_options=HeadlessOptions(
            navigation_timeout=0.1,
            wait_until=HeadlessWaitUntil.LOAD,
            post_load_delay_seconds=0.0,
        ),
    )

    assert result.ok is False
    assert result.fetch_info is None
    assert result.fetch_failure is not None
    assert result.fetch_failure.category == "timeout"
    assert result.fetch_failure.retryable is True


def test_deep_headless_captures_runtime_only_antibot_signals(
    live_headless_browser_available: None,
    live_server: LiveServerState,
    client: Wappalyzer,
) -> None:
    normal_headless = analyze_url(
        f"{live_server.base_url}/deep-runtime",
        client=client,
        fetch_options=FetchOptions(timeout=5.0, retries=0),
        headless_options=HeadlessOptions(
            wait_until=HeadlessWaitUntil.LOAD,
            post_load_delay_seconds=0.1,
        ),
    )
    deep_headless = analyze_url(
        f"{live_server.base_url}/deep-runtime",
        client=client,
        fetch_options=FetchOptions(timeout=5.0, retries=0),
        headless_options=HeadlessOptions(
            wait_until=HeadlessWaitUntil.LOAD,
            post_load_delay_seconds=0.1,
        ),
        deep_headless=DeepHeadlessOptions(),
        capture_artifacts=True,
    )

    assert normal_headless.anti_bot_findings == ()
    assert any(
        finding.vendor == "reCAPTCHA" for finding in deep_headless.anti_bot_findings
    )
    finding = next(
        finding
        for finding in deep_headless.anti_bot_findings
        if finding.vendor == "reCAPTCHA"
    )
    assert any(item.source == "runtime_marker" for item in finding.evidence)
    assert deep_headless.artifacts is not None
    assert deep_headless.artifacts.runtime_markers == ("grecaptcha",)
