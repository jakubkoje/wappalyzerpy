from __future__ import annotations

from wappalyzer_pure.patterns import parse_pattern


def test_parse_pattern_preserves_go_style_rewrites() -> None:
    parsed = parse_pattern("Mage.*\\;confidence:50")
    assert parsed.regex is not None
    assert parsed.regex.pattern == "Mage.{0,250}"
    assert parsed.confidence == 50


def test_parse_pattern_handles_version_regex() -> None:
    parsed = parse_pattern("jquery-([0-9.]+)\\.js\\;version:\\1")
    assert parsed.regex is not None
    assert parsed.regex.pattern == "jquery-([0-9.]{1,250})\\.js"
    assert parsed.version == "\\1"


def test_evaluate_extracts_complex_versions() -> None:
    parsed = parse_pattern(
        "(?:((?:\\d+\\.)+\\d+)\\/)?chroma(?:\\.min)?\\.js\\;version:\\1"
    )
    matched, version = parsed.evaluate("/ajax/libs/chroma-js/2.4.2/chroma.min.js")
    assert matched is True
    assert version == "2.4.2"


def test_blank_pattern_matches_anything() -> None:
    parsed = parse_pattern("")
    matched, version = parsed.evaluate("anything")
    assert matched is True
    assert version == ""
