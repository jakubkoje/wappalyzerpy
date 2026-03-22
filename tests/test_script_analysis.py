from __future__ import annotations

import pytest

from wappalyzer_pure.script_analysis import ScriptAnalysisOptions


def test_script_analysis_options_reject_negative_script_count() -> None:
    with pytest.raises(ValueError, match="max_external_scripts"):
        ScriptAnalysisOptions(max_external_scripts=-1)


def test_script_analysis_options_reject_zero_bytes_per_script() -> None:
    with pytest.raises(ValueError, match="max_bytes_per_script"):
        ScriptAnalysisOptions(max_bytes_per_script=0)


def test_script_analysis_options_reject_zero_total_script_bytes() -> None:
    with pytest.raises(ValueError, match="max_total_script_bytes"):
        ScriptAnalysisOptions(max_total_script_bytes=0)
