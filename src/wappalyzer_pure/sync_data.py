from __future__ import annotations

import argparse
import json
import string
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from urllib import request as urllib_request

DEFAULT_REPO = "enthec/webappanalyzer"
DEFAULT_REF = "main"
TECHNOLOGY_FILE_STEMS = tuple(string.ascii_lowercase) + ("_",)
REQUEST_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "wappalyzer-pure-sync/0.1.0",
}


@dataclass(frozen=True, slots=True)
class SyncPaths:
    fingerprints: Path
    categories: Path
    metadata: Path


@dataclass(frozen=True, slots=True)
class SyncResult:
    repo: str
    ref: str
    commit: str | None
    technologies: int
    categories: int
    fingerprints: Path
    categories_file: Path
    metadata: Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m wappalyzer_pure.sync_data")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--ref", default=DEFAULT_REF)
    parser.add_argument("--fingerprints-path", type=Path)
    parser.add_argument("--categories-path", type=Path)
    parser.add_argument("--metadata-path", type=Path)
    args = parser.parse_args(argv)

    active_paths = default_sync_paths()
    if args.fingerprints_path is not None:
        active_paths = SyncPaths(
            fingerprints=args.fingerprints_path,
            categories=active_paths.categories,
            metadata=active_paths.metadata,
        )
    if args.categories_path is not None:
        active_paths = SyncPaths(
            fingerprints=active_paths.fingerprints,
            categories=args.categories_path,
            metadata=active_paths.metadata,
        )
    if args.metadata_path is not None:
        active_paths = SyncPaths(
            fingerprints=active_paths.fingerprints,
            categories=active_paths.categories,
            metadata=args.metadata_path,
        )

    result = sync_package_data(repo=args.repo, ref=args.ref, paths=active_paths)
    print(
        f"synced {result.technologies} technologies and {result.categories} "
        f"categories from {result.repo}@{result.ref}"
    )
    if result.commit:
        print(f"upstream commit: {result.commit}")
    print(f"fingerprints: {result.fingerprints}")
    print(f"categories: {result.categories_file}")
    print(f"metadata: {result.metadata}")
    return 0


def default_sync_paths() -> SyncPaths:
    data_dir = Path(__file__).resolve().parent / "data"
    return SyncPaths(
        fingerprints=data_dir / "fingerprints_data.json",
        categories=data_dir / "categories_data.json",
        metadata=data_dir / "source_metadata.json",
    )


def sync_package_data(
    *,
    repo: str = DEFAULT_REPO,
    ref: str = DEFAULT_REF,
    paths: SyncPaths | None = None,
) -> SyncResult:
    active_paths = paths or default_sync_paths()
    technologies = _download_technologies(repo=repo, ref=ref)
    normalized_apps = {
        name: _normalize_fingerprint(payload)
        for name, payload in sorted(
            technologies.items(), key=lambda item: item[0].casefold()
        )
    }
    categories_payload = _download_categories(repo=repo, ref=ref)
    normalized_categories = _normalize_categories(categories_payload)
    commit = _fetch_commit_sha(repo=repo, ref=ref)
    metadata = {
        "source": {
            "repo": repo,
            "ref": ref,
            "commit": commit,
            "fetched_at_utc": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        },
        "counts": {
            "technologies": len(normalized_apps),
            "categories": len(normalized_categories),
            "technology_files": len(TECHNOLOGY_FILE_STEMS),
        },
    }

    _write_json(active_paths.fingerprints, {"apps": normalized_apps})
    _write_json(active_paths.categories, normalized_categories)
    _write_json(active_paths.metadata, metadata)

    return SyncResult(
        repo=repo,
        ref=ref,
        commit=commit,
        technologies=len(normalized_apps),
        categories=len(normalized_categories),
        fingerprints=active_paths.fingerprints,
        categories_file=active_paths.categories,
        metadata=active_paths.metadata,
    )


def _download_technologies(*, repo: str, ref: str) -> dict[str, Mapping[str, object]]:
    technologies: dict[str, Mapping[str, object]] = {}
    for stem in TECHNOLOGY_FILE_STEMS:
        payload = _download_json_object(
            _raw_url(repo, ref, f"src/technologies/{stem}.json")
        )
        for name, raw_fingerprint in payload.items():
            if not isinstance(raw_fingerprint, Mapping):
                raise TypeError(
                    f"invalid fingerprint payload for {name!r} in {stem}.json: "
                    f"{type(raw_fingerprint)!r}"
                )
            if name in technologies:
                raise ValueError(f"duplicate technology name encountered: {name}")
            technologies[name] = cast(Mapping[str, object], raw_fingerprint)
    return technologies


def _download_categories(*, repo: str, ref: str) -> Mapping[str, object]:
    return _download_json_object(_raw_url(repo, ref, "src/categories.json"))


def _fetch_commit_sha(*, repo: str, ref: str) -> str | None:
    url = f"https://api.github.com/repos/{repo}/commits/{ref}"
    try:
        payload = _download_json_object(url)
    except (OSError, ValueError, TypeError):
        return None
    sha = payload.get("sha")
    if isinstance(sha, str) and sha:
        return sha
    return None


def _raw_url(repo: str, ref: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"


def _download_json_object(url: str) -> dict[str, object]:
    request = urllib_request.Request(url, headers=REQUEST_HEADERS)
    with urllib_request.urlopen(request, timeout=30) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        payload = json.loads(response.read().decode(charset))
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object from {url}, got {type(payload)!r}")
    return payload


def _normalize_fingerprint(payload: Mapping[str, object]) -> dict[str, object]:
    normalized: dict[str, object] = {}

    cats = _normalize_integer_list(payload.get("cats"))
    if cats:
        normalized["cats"] = cats

    css = _normalize_string_or_list(payload.get("css"))
    if css:
        normalized["css"] = css

    dom = _normalize_dom(payload.get("dom"))
    if dom:
        normalized["dom"] = dom

    cookies = _normalize_string_map(
        payload.get("cookies"),
        lowercase_keys=True,
        lowercase_values=True,
    )
    if cookies:
        normalized["cookies"] = cookies

    js = _normalize_string_map(
        payload.get("js"),
        lowercase_keys=False,
        lowercase_values=False,
    )
    if js:
        normalized["js"] = js

    headers = _normalize_string_map(
        payload.get("headers"),
        lowercase_keys=True,
        lowercase_values=True,
    )
    if headers:
        normalized["headers"] = headers

    html = _normalize_string_or_list(payload.get("html"), lowercase=True)
    if html:
        normalized["html"] = html

    scripts = _normalize_string_or_list(payload.get("scripts"), lowercase=True)
    if scripts:
        normalized["scripts"] = scripts

    script_src = _normalize_string_or_list(payload.get("scriptSrc"), lowercase=True)
    if script_src:
        normalized["scriptSrc"] = script_src

    meta = _normalize_meta_map(payload.get("meta"))
    if meta:
        normalized["meta"] = meta

    implies = _normalize_string_or_list(payload.get("implies"))
    if implies:
        normalized["implies"] = implies

    for field_name in ("description", "website", "cpe", "icon"):
        value = payload.get(field_name)
        if value is None:
            continue
        text = _require_text(value, field_name)
        if text:
            normalized[field_name] = text

    return normalized


def _normalize_categories(payload: Mapping[str, object]) -> dict[str, object]:
    categories: dict[str, object] = {}
    for key in sorted(payload, key=lambda value: int(value)):
        value = payload[key]
        if not isinstance(value, Mapping):
            raise TypeError(f"invalid category payload for {key!r}: {type(value)!r}")
        categories[str(key)] = _sort_mapping(cast(Mapping[str, object], value))
    return categories


def _normalize_integer_list(value: object) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"expected a sequence of integers, got {type(value)!r}")
    return [_coerce_int(item) for item in value]


def _normalize_string_or_list(
    value: object,
    *,
    lowercase: bool = False,
) -> list[str]:
    if value is None:
        return []
    values = _as_string_sequence(value)
    normalized = [item.lower() if lowercase else item for item in values]
    return sorted(normalized)


def _normalize_string_map(
    value: object,
    *,
    lowercase_keys: bool,
    lowercase_values: bool,
) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"expected a mapping of strings, got {type(value)!r}")
    normalized: dict[str, str] = {}
    for key, raw_value in sorted(
        value.items(), key=lambda item: str(item[0]).casefold()
    ):
        key_text = _require_text(key, "mapping key")
        value_text = _require_text(raw_value, f"mapping value for {key_text!r}")
        normalized_key = key_text.lower() if lowercase_keys else key_text
        normalized_value = value_text.lower() if lowercase_values else value_text
        normalized[normalized_key] = normalized_value
    return normalized


def _normalize_meta_map(value: object) -> dict[str, list[str]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"expected a meta mapping, got {type(value)!r}")
    normalized: dict[str, list[str]] = {}
    for key, raw_value in sorted(
        value.items(), key=lambda item: str(item[0]).casefold()
    ):
        key_text = _require_text(key, "meta key").lower()
        if isinstance(raw_value, str):
            normalized[key_text] = [] if raw_value == "" else [raw_value.lower()]
            continue
        values = _normalize_string_or_list(raw_value, lowercase=True)
        normalized[key_text] = values
    return normalized


def _normalize_dom(value: object) -> dict[str, object]:
    if value is None:
        return {}
    if isinstance(value, str):
        return {value: {"exists": ""}}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        normalized: dict[str, object] = {}
        for item in value:
            normalized[_require_text(item, "dom selector")] = {"exists": ""}
        return dict(sorted(normalized.items(), key=lambda item: item[0].casefold()))
    if not isinstance(value, Mapping):
        raise TypeError(
            f"expected DOM data to be a string, list, or mapping, got {type(value)!r}"
        )
    normalized_mapping: dict[str, object] = {}
    for selector, payload in sorted(
        value.items(), key=lambda item: str(item[0]).casefold()
    ):
        selector_text = _require_text(selector, "dom selector")
        if not isinstance(payload, Mapping):
            raise TypeError(
                f"invalid dom payload for {selector_text!r}: {type(payload)!r}"
            )
        normalized_mapping[selector_text] = _sort_mapping(
            cast(Mapping[str, object], payload)
        )
    return normalized_mapping


def _as_string_sequence(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_require_text(item, "sequence item") for item in value]
    raise TypeError(f"expected a string or sequence of strings, got {type(value)!r}")


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"expected {label} to be a string, got {type(value)!r}")
    return value


def _coerce_int(value: object) -> int:
    if isinstance(value, bool):
        raise TypeError("boolean values are not valid integers in this context")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise TypeError(f"expected an integer value, got {type(value)!r}")


def _sort_mapping(value: Mapping[str, object]) -> dict[str, object]:
    normalized: dict[str, object] = {}
    for key, nested in sorted(value.items(), key=lambda item: str(item[0]).casefold()):
        key_text = _require_text(key, "mapping key")
        normalized[key_text] = _sort_value(nested)
    return normalized


def _sort_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _sort_mapping(cast(Mapping[str, object], value))
    if isinstance(value, list):
        return [_sort_value(item) for item in value]
    return value


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
