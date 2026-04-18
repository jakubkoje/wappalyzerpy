from __future__ import annotations

import pytest

from wappalyzer_pure.fetching import DEFAULT_BROWSER_USER_AGENT
from wappalyzer_pure.headless import (
    DeepHeadlessOptions,
    HeadlessOptions,
    build_headless_request_headers,
)


def test_headless_options_reject_invalid_values() -> None:
    with pytest.raises(ValueError, match="navigation_timeout"):
        HeadlessOptions(navigation_timeout=0)
    with pytest.raises(ValueError, match="post_load_delay_seconds"):
        HeadlessOptions(post_load_delay_seconds=-0.1)
    with pytest.raises(ValueError, match="viewport_width"):
        HeadlessOptions(viewport_width=0)
    with pytest.raises(ValueError, match="viewport_height"):
        HeadlessOptions(viewport_height=0)
    with pytest.raises(ValueError, match="locale"):
        HeadlessOptions(locale="")


def test_deep_headless_options_reject_invalid_values() -> None:
    with pytest.raises(ValueError, match="max_script_sources"):
        DeepHeadlessOptions(max_script_sources=-1)
    with pytest.raises(ValueError, match="max_frame_sources"):
        DeepHeadlessOptions(max_frame_sources=-1)
    with pytest.raises(ValueError, match="max_resource_urls"):
        DeepHeadlessOptions(max_resource_urls=-1)
    with pytest.raises(ValueError, match="runtime_markers"):
        DeepHeadlessOptions(runtime_markers=("grecaptcha", ""))


def test_build_headless_request_headers_preserves_overrides() -> None:
    headers = build_headless_request_headers(
        request_headers={
            "X-Test": "1",
            "User-Agent": "Override/2.0",
        },
        user_agent="Ignored/1.0",
    )

    assert headers == {
        "User-Agent": "Override/2.0",
        "X-Test": "1",
    }


def test_build_headless_request_headers_uses_default_browser_user_agent() -> None:
    headers = build_headless_request_headers(
        request_headers=None,
        user_agent=None,
    )

    assert headers == {
        "User-Agent": DEFAULT_BROWSER_USER_AGENT,
    }
