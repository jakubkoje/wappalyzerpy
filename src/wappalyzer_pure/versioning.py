from __future__ import annotations

import argparse
import re
from pathlib import Path

VERSION_PATTERN = re.compile(r'^version = "(\d+)\.(\d+)\.(\d+)"$', re.MULTILINE)


def read_project_version(pyproject_path: Path) -> str:
    content = pyproject_path.read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(content)
    if match is None:
        raise ValueError(f"could not find project version in {pyproject_path}")
    return ".".join(match.groups())


def bump_patch_version(pyproject_path: Path) -> str:
    content = pyproject_path.read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(content)
    if match is None:
        raise ValueError(f"could not find project version in {pyproject_path}")

    major, minor, patch = (int(part) for part in match.groups())
    next_version = f"{major}.{minor}.{patch + 1}"
    updated = VERSION_PATTERN.sub(f'version = "{next_version}"', content, count=1)
    pyproject_path.write_text(updated, encoding="utf-8")
    return next_version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m wappalyzer_pure.versioning")
    parser.add_argument("--path", type=Path, default=Path("pyproject.toml"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--print-version", action="store_true")
    group.add_argument("--bump-patch", action="store_true")
    args = parser.parse_args(argv)

    if args.print_version:
        print(read_project_version(args.path))
        return 0

    print(bump_patch_version(args.path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
