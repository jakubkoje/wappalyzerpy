from __future__ import annotations

from pathlib import Path

from wappalyzer_pure.versioning import bump_patch_version, read_project_version


def test_read_project_version(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "demo"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )

    assert read_project_version(pyproject) == "1.2.3"


def test_bump_patch_version_updates_file(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "demo"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )

    next_version = bump_patch_version(pyproject)

    assert next_version == "1.2.4"
    assert read_project_version(pyproject) == "1.2.4"
