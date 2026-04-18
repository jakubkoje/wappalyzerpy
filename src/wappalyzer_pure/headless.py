from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .exceptions import HeadlessUnavailableError
from .fetching import (
    DEFAULT_BROWSER_USER_AGENT,
    FetchHeaderProfile,
    FetchOptions,
    FetchTLSMode,
    FetchedResponse,
)
from .models import BrowserSignals, FetchFailure, FetchInfo


class HeadlessBrowser(str, Enum):
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"


class HeadlessWaitUntil(str, Enum):
    COMMIT = "commit"
    DOMCONTENTLOADED = "domcontentloaded"
    LOAD = "load"
    NETWORKIDLE = "networkidle"


_DEFAULT_RUNTIME_MARKERS = (
    "_pxAppId",
    "grecaptcha",
    "___grecaptcha_cfg",
    "hcaptcha",
    "initGeetest",
    "GeetestCaptchaObj",
    "geetest",
    "turnstile",
    "_cf_chl_opt",
    "istlWasHere",
)


@dataclass(frozen=True, slots=True)
class HeadlessOptions:
    browser: HeadlessBrowser = HeadlessBrowser.CHROMIUM
    navigation_timeout: float | None = None
    wait_until: HeadlessWaitUntil = HeadlessWaitUntil.LOAD
    post_load_delay_seconds: float = 0.5
    viewport_width: int = 1440
    viewport_height: int = 900
    locale: str = "en-US"
    simulate_interaction: bool = False

    def __post_init__(self) -> None:
        if self.navigation_timeout is not None and self.navigation_timeout <= 0:
            raise ValueError("navigation_timeout must be greater than zero")
        if self.post_load_delay_seconds < 0:
            raise ValueError("post_load_delay_seconds must be zero or greater")
        if self.viewport_width <= 0:
            raise ValueError("viewport_width must be greater than zero")
        if self.viewport_height <= 0:
            raise ValueError("viewport_height must be greater than zero")
        if not self.locale:
            raise ValueError("locale must not be empty")


@dataclass(frozen=True, slots=True)
class DeepHeadlessOptions:
    capture_dom_sources: bool = True
    capture_frame_sources: bool = True
    capture_resource_urls: bool = True
    capture_cookies: bool = True
    runtime_markers: tuple[str, ...] = _DEFAULT_RUNTIME_MARKERS
    max_script_sources: int = 128
    max_frame_sources: int = 64
    max_resource_urls: int = 256

    def __post_init__(self) -> None:
        if self.max_script_sources < 0:
            raise ValueError("max_script_sources must be zero or greater")
        if self.max_frame_sources < 0:
            raise ValueError("max_frame_sources must be zero or greater")
        if self.max_resource_urls < 0:
            raise ValueError("max_resource_urls must be zero or greater")
        if any(not marker for marker in self.runtime_markers):
            raise ValueError("runtime_markers must not contain empty values")


class HeadlessFetcher(Protocol):
    def fetch_page(
        self,
        url: str,
        *,
        request_headers: Mapping[str, str],
        fetch_options: FetchOptions,
        headless_options: HeadlessOptions,
        deep_headless: DeepHeadlessOptions | None = None,
    ) -> FetchedResponse | FetchFailure: ...


def build_headless_request_headers(
    *,
    request_headers: Mapping[str, str] | None,
    user_agent: str | None,
) -> dict[str, str]:
    headers = {"User-Agent": user_agent or DEFAULT_BROWSER_USER_AGENT}
    if request_headers:
        headers.update({str(key): str(value) for key, value in request_headers.items()})
    return headers


def fetch_url_headless(
    url: str,
    *,
    request_headers: Mapping[str, str],
    fetch_options: FetchOptions,
    headless_options: HeadlessOptions,
    deep_headless: DeepHeadlessOptions | None = None,
    fetcher: HeadlessFetcher | None = None,
) -> FetchedResponse | FetchFailure:
    active_fetcher = fetcher or PlaywrightHeadlessFetcher()
    return active_fetcher.fetch_page(
        url,
        request_headers=request_headers,
        fetch_options=fetch_options,
        headless_options=headless_options,
        deep_headless=deep_headless,
    )


class PlaywrightHeadlessFetcher:
    def fetch_page(
        self,
        url: str,
        *,
        request_headers: Mapping[str, str],
        fetch_options: FetchOptions,
        headless_options: HeadlessOptions,
        deep_headless: DeepHeadlessOptions | None = None,
    ) -> FetchedResponse | FetchFailure:
        sync_playwright, playwright_error_type, playwright_timeout_type = (
            _load_playwright_sync_api()
        )
        max_attempts = fetch_options.retries + 1

        for attempt in range(1, max_attempts + 1):
            try:
                with sync_playwright() as playwright:
                    browser_type = getattr(playwright, headless_options.browser.value)
                    try:
                        browser = browser_type.launch(headless=True)
                    except playwright_error_type as exc:
                        raise HeadlessUnavailableError(
                            _format_headless_unavailable_message(
                                browser=headless_options.browser.value,
                                message=str(exc),
                            )
                        ) from exc

                    try:
                        result = self._fetch_attempt(
                            browser=browser,
                            url=url,
                            request_headers=request_headers,
                            fetch_options=fetch_options,
                            headless_options=headless_options,
                            deep_headless=deep_headless,
                            attempt=attempt,
                            playwright_error_type=playwright_error_type,
                            playwright_timeout_type=playwright_timeout_type,
                        )
                    finally:
                        try:
                            browser.close()
                        except Exception:  # noqa: BLE001
                            pass
            except HeadlessUnavailableError:
                raise

            if not isinstance(result, FetchFailure):
                return result
            if not result.retryable or attempt >= max_attempts:
                return result
            if fetch_options.retry_backoff_seconds > 0:
                time.sleep(fetch_options.retry_backoff_seconds * attempt)

        return FetchFailure(
            category="browser",
            error_type="RuntimeError",
            message="failed to obtain a rendered browser response",
            retryable=False,
            attempts=max_attempts,
        )

    def _fetch_attempt(
        self,
        *,
        browser: object,
        url: str,
        request_headers: Mapping[str, str],
        fetch_options: FetchOptions,
        headless_options: HeadlessOptions,
        deep_headless: DeepHeadlessOptions | None,
        attempt: int,
        playwright_error_type: type[Exception],
        playwright_timeout_type: type[Exception],
    ) -> FetchedResponse | FetchFailure:
        user_agent, extra_headers = _split_user_agent_header(request_headers)
        context_kwargs: dict[str, object] = {
            "user_agent": user_agent or DEFAULT_BROWSER_USER_AGENT,
            "locale": headless_options.locale,
            "viewport": {
                "width": headless_options.viewport_width,
                "height": headless_options.viewport_height,
            },
            "ignore_https_errors": fetch_options.tls_mode
            is FetchTLSMode.INSECURE,
        }
        if extra_headers:
            context_kwargs["extra_http_headers"] = extra_headers

        browser_context = browser.new_context(
            **context_kwargs,
        )

        try:
            page = browser_context.new_page()
            timeout_ms = int(
                1000
                * (
                    headless_options.navigation_timeout
                    if headless_options.navigation_timeout is not None
                    else fetch_options.timeout
                )
            )
            try:
                response = page.goto(
                    url,
                    wait_until=headless_options.wait_until.value,
                    timeout=timeout_ms,
                )
                if headless_options.post_load_delay_seconds > 0:
                    page.wait_for_timeout(
                        int(headless_options.post_load_delay_seconds * 1000)
                    )
                if headless_options.simulate_interaction:
                    _simulate_scroll_interaction(page)
                body = page.content().encode("utf-8")
                browser_signals = (
                    _collect_browser_signals(
                        page=page,
                        browser_context=browser_context,
                        options=deep_headless,
                    )
                    if deep_headless is not None
                    else None
                )
            except playwright_timeout_type as exc:
                return FetchFailure(
                    category="timeout",
                    error_type=type(exc).__name__,
                    message=str(exc),
                    retryable=True,
                    attempts=attempt,
                )
            except playwright_error_type as exc:
                return _classify_playwright_error(exc, attempts=attempt)

            return FetchedResponse(
                target_url=url,
                final_url=str(page.url),
                status_code=_extract_response_status_code(response),
                headers=_headers_from_playwright_response(response),
                body=body,
                fetch_info=FetchInfo(
                    attempts=attempt,
                    partial_response=False,
                    header_profile=FetchHeaderProfile.BROWSER.value,
                    tls_mode=fetch_options.tls_mode.value,
                    transport="headless",
                    browser=headless_options.browser.value,
                    wait_until=headless_options.wait_until.value,
                ),
                browser_signals=browser_signals,
            )
        finally:
            try:
                browser_context.close()
            except Exception:  # noqa: BLE001
                pass


def _simulate_scroll_interaction(page: object) -> None:
    """Scroll, then focus the first visible text/search input to trigger lazy antibot widgets."""
    # Phase 1: gradual scroll to trigger intersection observers
    _call_member(
        page,
        "evaluate",
        """
        async () => {
            const totalHeight = Math.max(
                document.body ? document.body.scrollHeight : 0,
                document.documentElement.scrollHeight,
                800
            );
            const steps = 4;
            for (let i = 1; i <= steps; i++) {
                window.scrollTo({ top: Math.floor(totalHeight * i / steps), behavior: 'instant' });
                await new Promise(r => setTimeout(r, 250));
            }
            window.scrollTo({ top: 0, behavior: 'instant' });
            await new Promise(r => setTimeout(r, 300));
        }
        """,
    )
    _call_member(page, "wait_for_timeout", 400)
    # Phase 2: focus the first visible interactive input to trigger captcha widgets
    # (GeeTest and similar load on focus/click of search/text fields)
    _call_member(
        page,
        "evaluate",
        """
        async () => {
            const candidates = [
                'input[type="search"]',
                'input[type="text"]:not([hidden]):not([disabled])',
                'input[type="email"]:not([hidden]):not([disabled])',
            ];
            for (const sel of candidates) {
                const el = document.querySelector(sel);
                if (!el) continue;
                const rect = el.getBoundingClientRect();
                if (rect.width < 10 || rect.height < 5) continue;
                el.scrollIntoView({ behavior: 'instant', block: 'center' });
                await new Promise(r => setTimeout(r, 200));
                el.focus();
                el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                el.dispatchEvent(new MouseEvent('click', { bubbles: true }));
                await new Promise(r => setTimeout(r, 900));
                break;
            }
        }
        """,
    )
    _call_member(page, "wait_for_timeout", 600)


def _load_playwright_sync_api() -> tuple[Any, type[Exception], type[Exception]]:
    try:
        from playwright.sync_api import (  # pyright: ignore[reportMissingImports]
            Error as PlaywrightError,
            TimeoutError as PlaywrightTimeoutError,
            sync_playwright,
        )
    except ImportError as exc:
        raise HeadlessUnavailableError(
            "headless analysis requires the optional Playwright dependency. "
            "Install it with `uv sync --extra headless` and download a browser "
            "with `uv run playwright install chromium`."
        ) from exc

    return sync_playwright, PlaywrightError, PlaywrightTimeoutError


def _split_user_agent_header(
    request_headers: Mapping[str, str],
) -> tuple[str | None, dict[str, str]]:
    user_agent: str | None = None
    extra_headers: dict[str, str] = {}

    for key, value in request_headers.items():
        key_text = str(key)
        value_text = str(value)
        if key_text.casefold() == "user-agent":
            user_agent = value_text
            continue
        extra_headers[key_text] = value_text

    return user_agent, extra_headers


def _collect_browser_signals(
    *,
    page: object,
    browser_context: object,
    options: DeepHeadlessOptions,
) -> BrowserSignals:
    dom_sources = (
        _collect_dom_sources(
            page,
            "script",
            attribute="src",
            limit=options.max_script_sources,
        )
        if options.capture_dom_sources
        else ()
    )
    frame_sources = (
        _merge_unique_strings(
            _collect_dom_sources(
                page,
                "iframe",
                attribute="src",
                limit=options.max_frame_sources,
            ),
            _collect_frame_urls(page, limit=options.max_frame_sources),
        )
        if options.capture_frame_sources
        else ()
    )
    resource_urls = (
        _collect_resource_urls(page, limit=options.max_resource_urls)
        if options.capture_resource_urls
        else ()
    )
    cookie_header = (
        _build_cookie_header(
            _call_member(browser_context, "cookies", [_stringify_scalar(_call_member(page, "url"))])
        )
        if options.capture_cookies
        else None
    )
    runtime_markers = (
        _collect_runtime_markers(page, options.runtime_markers)
        if options.runtime_markers
        else ()
    )
    return BrowserSignals(
        cookie_header=cookie_header,
        script_sources=dom_sources,
        iframe_sources=frame_sources,
        resource_urls=resource_urls,
        runtime_markers=runtime_markers,
    )


def _collect_dom_sources(
    page: object,
    selector: str,
    *,
    attribute: str,
    limit: int,
) -> tuple[str, ...]:
    if limit <= 0:
        return ()
    values = _call_member(
        page,
        "evaluate",
        f"""
        ({{ selector, attribute, limit }}) => {{
          const values = [];
          const seen = new Set();
          for (const node of document.querySelectorAll(selector)) {{
            const value = node.getAttribute(attribute) || '';
            if (!value || seen.has(value)) {{
              continue;
            }}
            seen.add(value);
            values.push(value);
            if (values.length >= limit) {{
              break;
            }}
          }}
          return values;
        }}
        """,
        {"selector": selector, "attribute": attribute, "limit": limit},
    )
    return _coerce_string_tuple(values, limit=limit)


def _collect_frame_urls(page: object, *, limit: int) -> tuple[str, ...]:
    if limit <= 0:
        return ()
    frames = _call_member(page, "frames")
    if not _is_non_string_sequence(frames):
        return ()
    values: list[str] = []
    seen: set[str] = set()
    main_url = _stringify_scalar(_call_member(page, "url"))
    for frame in frames:
        url = _stringify_scalar(_call_member(frame, "url"))
        if not url or url == main_url or url in seen:
            continue
        seen.add(url)
        values.append(url)
        if len(values) >= limit:
            break
    return tuple(values)


def _collect_resource_urls(page: object, *, limit: int) -> tuple[str, ...]:
    if limit <= 0:
        return ()
    values = _call_member(
        page,
        "evaluate",
        """
        (limit) => {
          const values = [];
          const seen = new Set();
          for (const entry of performance.getEntriesByType('resource')) {
            const value = typeof entry.name === 'string' ? entry.name : '';
            if (!value || seen.has(value)) {
              continue;
            }
            seen.add(value);
            values.push(value);
            if (values.length >= limit) {
              break;
            }
          }
          return values;
        }
        """,
        limit,
    )
    return _coerce_string_tuple(values, limit=limit)


def _collect_runtime_markers(
    page: object,
    markers: tuple[str, ...],
) -> tuple[str, ...]:
    values = _call_member(
        page,
        "evaluate",
        """
        (markers) => {
          const values = [];
          for (const marker of markers) {
            const parts = marker.split('.');
            let current = window;
            let present = true;
            for (const part of parts) {
              if (current == null || !(part in current)) {
                present = false;
                break;
              }
              current = current[part];
            }
            if (present && current != null) {
              values.push(marker);
            }
          }
          return values;
        }
        """,
        list(markers),
    )
    return tuple(
        item.casefold() for item in _coerce_string_tuple(values, limit=len(markers))
    )


def _build_cookie_header(cookies_payload: object) -> str | None:
    if not _is_non_string_sequence(cookies_payload):
        return None
    pairs: list[str] = []
    seen: set[str] = set()
    for item in cookies_payload:
        if not isinstance(item, Mapping):
            continue
        name = _stringify_scalar(item.get("name"))
        value = _stringify_scalar(item.get("value"))
        if not name or name in seen:
            continue
        seen.add(name)
        pairs.append(f"{name}={value}")
    if not pairs:
        return None
    return "; ".join(pairs)


def _coerce_string_tuple(value: object, *, limit: int) -> tuple[str, ...]:
    if not _is_non_string_sequence(value):
        return ()
    values: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _stringify_scalar(item)
        if not text or text in seen:
            continue
        seen.add(text)
        values.append(text)
        if len(values) >= limit:
            break
    return tuple(values)


def _merge_unique_strings(
    first: tuple[str, ...],
    second: tuple[str, ...],
) -> tuple[str, ...]:
    values = list(first)
    seen = set(first)
    for item in second:
        if not item or item in seen:
            continue
        seen.add(item)
        values.append(item)
    return tuple(values)


def _stringify_scalar(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _headers_from_playwright_response(response: object | None) -> dict[str, list[str]]:
    if response is None:
        return {}

    headers: dict[str, list[str]] = {}
    header_items = _call_member(response, "headers_array")
    if _is_non_string_sequence(header_items):
        for item in header_items:
            if not isinstance(item, Mapping):
                continue
            name = item.get("name")
            value = item.get("value")
            if name is None or value is None:
                continue
            headers.setdefault(str(name), []).append(str(value))
        if headers:
            return headers

    all_headers = _call_member(response, "all_headers")
    if not isinstance(all_headers, Mapping):
        all_headers = _call_member(response, "headers")
    if isinstance(all_headers, Mapping):
        for key, value in all_headers.items():
            if value is None:
                continue
            headers.setdefault(str(key), []).append(str(value))

    set_cookie_values = _header_values(response, "set-cookie")
    if set_cookie_values:
        headers["set-cookie"] = set_cookie_values
    return headers


def _header_values(response: object, name: str) -> list[str]:
    values = _call_member(response, "header_values", name)
    if _is_non_string_sequence(values):
        return [str(item) for item in values if item is not None]

    value = _call_member(response, "header_value", name)
    if value is None:
        return []
    return [str(value)]


def _extract_response_status_code(response: object | None) -> int | None:
    if response is None:
        return None
    value = _call_member(response, "status")
    if isinstance(value, int):
        return value
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _call_member(target: object, name: str, *args: object) -> Any:
    if not hasattr(target, name):
        return None
    member = getattr(target, name)
    if callable(member):
        try:
            return member(*args)
        except Exception:  # noqa: BLE001
            return None
    if args:
        return None
    return member


def _is_non_string_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    )


def _classify_playwright_error(exc: Exception, *, attempts: int) -> FetchFailure:
    message = str(exc)
    lowered_message = message.casefold()

    if "timeout" in lowered_message or "timed out" in lowered_message:
        category = "timeout"
        retryable = True
    elif "certificate" in lowered_message or "ssl" in lowered_message:
        category = "tls"
        retryable = False
    elif "invalid url" in lowered_message:
        category = "invalid_url"
        retryable = False
    elif any(
        marker in lowered_message
        for marker in (
            "net::",
            "connection",
            "dns",
            "name not resolved",
            "connection reset",
            "connection refused",
        )
    ):
        category = "network"
        retryable = True
    else:
        category = "browser"
        retryable = False

    return FetchFailure(
        category=category,
        error_type=type(exc).__name__,
        message=message,
        retryable=retryable,
        attempts=attempts,
    )


def _format_headless_unavailable_message(*, browser: str, message: str) -> str:
    return (
        "headless analysis requires a local Playwright browser runtime. "
        "Install it with `uv sync --extra headless` and "
        f"`uv run playwright install {browser}`. Original error: {message}"
    )
