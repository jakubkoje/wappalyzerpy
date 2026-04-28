from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from wappalyzer_pure.fetching import FetchOptions
from wappalyzer_pure.headless import DeepHeadlessOptions, HeadlessOptions
from wappalyzer_pure.models import AnalysisResult, AntiBotFinding
from wappalyzer_pure.script_analysis import ScriptAnalysisOptions

RUNNER_PATH = (
    Path(__file__).resolve().parents[1] / "examples" / "dataset" / "run_dataset_scan.py"
)


def _load_dataset_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("run_dataset_scan", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_dataset_scan = cast(Any, _load_dataset_runner())


def test_scan_url_uses_headless_fallback_only_after_http_miss(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_analyze_url(url: str, **kwargs: object) -> AnalysisResult:
        calls.append({"url": url, **kwargs})
        if len(calls) == 1:
            return AnalysisResult(target_url=url, final_url=url, status_code=200)
        return AnalysisResult(
            target_url=url,
            final_url=url,
            status_code=200,
            anti_bot_findings=(
                AntiBotFinding(vendor="reCAPTCHA", score=3, confidence="medium"),
            ),
        )

    monkeypatch.setattr(run_dataset_scan, "analyze_url", fake_analyze_url)
    fallback_headless = HeadlessOptions()
    fallback_deep = DeepHeadlessOptions()

    json_record, csv_record = run_dataset_scan._scan_url(
        "https://example.com",
        source="merged",
        fetch_options=FetchOptions(),
        script_analysis=ScriptAnalysisOptions(),
        security_only=False,
        headless_options=None,
        deep_headless=None,
        fallback_headless_options=fallback_headless,
        fallback_deep_headless=fallback_deep,
    )

    assert len(calls) == 2
    assert calls[0]["headless_options"] is None
    assert calls[0]["deep_headless"] is None
    assert calls[1]["headless_options"] is fallback_headless
    assert calls[1]["deep_headless"] is fallback_deep
    assert json_record["source"] == "https://example.com"
    assert csv_record["anti_bot_vendors"] == "reCAPTCHA"


def test_scan_url_skips_headless_fallback_when_http_finds_antibot(
    monkeypatch,
) -> None:
    calls: list[dict[str, object]] = []

    def fake_analyze_url(url: str, **kwargs: object) -> AnalysisResult:
        calls.append({"url": url, **kwargs})
        return AnalysisResult(
            target_url=url,
            final_url=url,
            status_code=403,
            anti_bot_findings=(
                AntiBotFinding(vendor="Akamai", score=4, confidence="medium"),
            ),
        )

    monkeypatch.setattr(run_dataset_scan, "analyze_url", fake_analyze_url)

    _, csv_record = run_dataset_scan._scan_url(
        "https://example.com",
        source="merged",
        fetch_options=FetchOptions(),
        script_analysis=ScriptAnalysisOptions(),
        security_only=False,
        headless_options=None,
        deep_headless=None,
        fallback_headless_options=HeadlessOptions(),
        fallback_deep_headless=DeepHeadlessOptions(),
    )

    assert len(calls) == 1
    assert csv_record["anti_bot_vendors"] == "Akamai"
