from __future__ import annotations

import json
from typing import Any

from wappalyzer_pure import AnalysisResult, cli


def test_scan_command_passes_headless_options_to_analyze_url(
    capsys: Any,
    monkeypatch: Any,
) -> None:
    captured: dict[str, object] = {}

    def fake_analyze_url(url: str, **kwargs: object) -> AnalysisResult:
        captured["url"] = url
        captured.update(kwargs)
        return AnalysisResult(
            target_url=url,
            final_url=url,
            status_code=200,
        )

    monkeypatch.setattr(cli, "analyze_url", fake_analyze_url)

    exit_code = cli.main(
        [
            "scan",
            "https://example.com",
            "--headless",
            "--deep-headless",
            "--headless-browser",
            "firefox",
            "--headless-timeout",
            "12",
            "--headless-wait-until",
            "load",
            "--headless-post-load-delay",
            "0.25",
            "--json",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert captured["url"] == "https://example.com"
    headless_options = captured["headless_options"]
    assert headless_options is not None
    assert headless_options.browser.value == "firefox"
    assert headless_options.navigation_timeout == 12.0
    assert headless_options.wait_until.value == "load"
    assert headless_options.post_load_delay_seconds == 0.25
    assert captured["deep_headless"] is True
    assert output["status_code"] == 200
