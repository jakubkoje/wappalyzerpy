from __future__ import annotations

import argparse
import hashlib
import json
import string
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from urllib import request as urllib_request

from .antibot_aliases import (
    anti_bot_aliases_filename,
    derive_anti_bot_alias_catalog,
    serialize_anti_bot_alias_catalog,
)
from .antibot_catalog import (
    anti_bot_technologies_filename,
    derive_anti_bot_technology_catalog,
    serialize_anti_bot_technology_catalog,
)
from .data_sources import (
    DEFAULT_FINGERPRINT_DATA_SOURCE,
    FingerprintDataSource,
    categories_filename,
    fingerprints_filename,
    normalize_fingerprint_data_source,
)

DEFAULT_REF = "main"
TECHNOLOGY_FILE_STEMS = tuple(string.ascii_lowercase) + ("_",)
REQUEST_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "wappalyzer-pure-sync/0.1.0",
}
CURATED_ANTI_BOT_RULE_FILES = (
    "anti_bot_signals_data.json",
    "anti_bot_catalog_rules.json",
    "anti_bot_alias_rules.json",
)
NormalizedApps = dict[str, dict[str, object]]
NormalizedCategories = dict[str, object]


@dataclass(frozen=True, slots=True)
class UpstreamSource:
    source: FingerprintDataSource
    repo: str
    ref: str = DEFAULT_REF


UPSTREAM_SOURCES: dict[FingerprintDataSource, UpstreamSource] = {
    FingerprintDataSource.ENTHEC: UpstreamSource(
        source=FingerprintDataSource.ENTHEC,
        repo="enthec/webappanalyzer",
    ),
    FingerprintDataSource.HTTPARCHIVE: UpstreamSource(
        source=FingerprintDataSource.HTTPARCHIVE,
        repo="HTTPArchive/wappalyzer",
    ),
}
UPSTREAM_DATA_SOURCES = tuple(UPSTREAM_SOURCES)


@dataclass(frozen=True, slots=True)
class DatasetPaths:
    fingerprints: Path
    categories: Path


@dataclass(frozen=True, slots=True)
class SyncPaths:
    datasets: dict[FingerprintDataSource, DatasetPaths]
    metadata: Path


@dataclass(frozen=True, slots=True)
class SourceSyncResult:
    source: FingerprintDataSource
    repo: str
    ref: str
    commit: str | None
    technologies: int
    categories: int
    fingerprints: Path
    categories_file: Path


@dataclass(frozen=True, slots=True)
class SyncResult:
    sources: dict[FingerprintDataSource, SourceSyncResult]
    metadata: Path
    comparison: dict[str, object]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m wappalyzer_pure.sync_data")
    parser.add_argument(
        "--source",
        choices=["all", *(source.value for source in UPSTREAM_DATA_SOURCES)],
        default="all",
        help="which packaged fingerprint source to refresh",
    )
    parser.add_argument("--repo")
    parser.add_argument("--ref")
    parser.add_argument("--fingerprints-path", type=Path)
    parser.add_argument("--categories-path", type=Path)
    parser.add_argument("--metadata-path", type=Path)
    args = parser.parse_args(argv)

    selected_source = None
    if args.source != "all":
        selected_source = normalize_fingerprint_data_source(args.source)

    if selected_source is None and (
        args.repo is not None
        or args.ref is not None
        or args.fingerprints_path is not None
        or args.categories_path is not None
    ):
        parser.error(
            "--repo, --ref, --fingerprints-path, and --categories-path require "
            "a single --source"
        )

    active_paths = default_sync_paths(selected_source)
    if args.metadata_path is not None:
        active_paths = SyncPaths(
            datasets=active_paths.datasets,
            metadata=args.metadata_path,
        )
    if selected_source is not None and args.fingerprints_path is not None:
        active_paths = _override_dataset_paths(
            active_paths,
            selected_source,
            fingerprints=args.fingerprints_path,
        )
    if selected_source is not None and args.categories_path is not None:
        active_paths = _override_dataset_paths(
            active_paths,
            selected_source,
            categories=args.categories_path,
        )

    result = sync_package_data(
        source=selected_source,
        repo=args.repo,
        ref=args.ref,
        paths=active_paths,
    )
    for source in sorted(result.sources, key=lambda item: item.value):
        source_result = result.sources[source]
        print(
            f"[{source.value}] synced {source_result.technologies} technologies and "
            f"{source_result.categories} categories from "
            f"{source_result.repo}@{source_result.ref}"
        )
        if source_result.commit:
            print(f"[{source.value}] upstream commit: {source_result.commit}")
        print(f"[{source.value}] fingerprints: {source_result.fingerprints}")
        print(f"[{source.value}] categories: {source_result.categories_file}")
    print(f"metadata: {result.metadata}")
    return 0


def default_sync_paths(
    source: FingerprintDataSource | str | None = None,
) -> SyncPaths:
    package_data_dir = Path(__file__).resolve().parent / "data"
    fingerprints_dir = package_data_dir / "fingerprints"
    categories_dir = package_data_dir / "categories"
    project_root = Path(__file__).resolve().parents[2]
    if source is None:
        selected_sources = (
            FingerprintDataSource.MERGED,
            *UPSTREAM_DATA_SOURCES,
        )
    else:
        selected_sources = (normalize_fingerprint_data_source(source),)
    datasets = {
        source_value: DatasetPaths(
            fingerprints=fingerprints_dir / fingerprints_filename(source_value),
            categories=categories_dir / categories_filename(source_value),
        )
        for source_value in selected_sources
    }
    return SyncPaths(
        datasets=datasets,
        metadata=project_root / ".github" / "data" / "source_metadata.json",
    )


def sync_package_data(
    *,
    source: FingerprintDataSource | str | None = None,
    repo: str | None = None,
    ref: str | None = None,
    paths: SyncPaths | None = None,
) -> SyncResult:
    selected_source = (
        None if source is None else normalize_fingerprint_data_source(source)
    )
    if selected_source is FingerprintDataSource.MERGED:
        raise ValueError(
            "sync_package_data does not accept the generated merged source"
        )
    active_paths = paths or default_sync_paths(selected_source)
    source_results: dict[FingerprintDataSource, SourceSyncResult] = {}
    comparison_input: dict[
        FingerprintDataSource, tuple[NormalizedApps, NormalizedCategories]
    ] = {}
    fetched_at_utc = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    for source_value in _selected_sources(selected_source):
        upstream = _resolve_upstream_source(source_value, repo=repo, ref=ref)
        dataset_paths = active_paths.datasets[source_value]
        technologies = _download_technologies(repo=upstream.repo, ref=upstream.ref)
        normalized_apps: NormalizedApps = {
            name: _normalize_fingerprint(payload)
            for name, payload in sorted(
                technologies.items(), key=lambda item: item[0].casefold()
            )
        }
        categories_payload = _download_categories(repo=upstream.repo, ref=upstream.ref)
        normalized_categories = _normalize_categories(categories_payload)
        commit = _fetch_commit_sha(repo=upstream.repo, ref=upstream.ref)

        _write_json(dataset_paths.fingerprints, {"apps": normalized_apps})
        _write_json(dataset_paths.categories, normalized_categories)

        source_results[source_value] = SourceSyncResult(
            source=source_value,
            repo=upstream.repo,
            ref=upstream.ref,
            commit=commit,
            technologies=len(normalized_apps),
            categories=len(normalized_categories),
            fingerprints=dataset_paths.fingerprints,
            categories_file=dataset_paths.categories,
        )
        comparison_input[source_value] = (normalized_apps, normalized_categories)

    if selected_source is None:
        merged_apps, merged_categories = _build_merged_dataset(comparison_input)
        merged_paths = active_paths.datasets[FingerprintDataSource.MERGED]
        _write_json(merged_paths.fingerprints, {"apps": merged_apps})
        _write_json(merged_paths.categories, merged_categories)
        source_results[FingerprintDataSource.MERGED] = SourceSyncResult(
            source=FingerprintDataSource.MERGED,
            repo="local-merge",
            ref="generated",
            commit=None,
            technologies=len(merged_apps),
            categories=len(merged_categories),
            fingerprints=merged_paths.fingerprints,
            categories_file=merged_paths.categories,
        )
        anti_bot_catalog = derive_anti_bot_technology_catalog(
            merged_apps,
            merged_categories,
        )
    else:
        source_apps, source_categories = comparison_input[selected_source]
        anti_bot_catalog = derive_anti_bot_technology_catalog(
            source_apps,
            source_categories,
        )
    anti_bot_aliases = derive_anti_bot_alias_catalog(anti_bot_catalog)

    data_dir = Path(__file__).resolve().parent / "data" / "antibot"
    _write_json(
        data_dir / anti_bot_technologies_filename(),
        serialize_anti_bot_technology_catalog(anti_bot_catalog),
    )
    _write_json(
        data_dir / anti_bot_aliases_filename(),
        serialize_anti_bot_alias_catalog(anti_bot_aliases),
    )

    metadata = _build_metadata(
        source_results=source_results,
        comparison_input=comparison_input,
        fetched_at_utc=fetched_at_utc,
        anti_bot_technologies_count=len(anti_bot_catalog),
        anti_bot_technologies_source=(
            FingerprintDataSource.MERGED.value
            if selected_source is None
            else selected_source.value
        ),
        anti_bot_vendor_aliases_count=len(anti_bot_aliases.vendor_aliases),
        anti_bot_product_aliases_count=len(anti_bot_aliases.product_aliases),
    )
    _write_json(active_paths.metadata, metadata)
    return SyncResult(
        sources=source_results,
        metadata=active_paths.metadata,
        comparison=cast(dict[str, object], metadata.get("comparison", {})),
    )


def _selected_sources(
    source: FingerprintDataSource | None,
) -> tuple[FingerprintDataSource, ...]:
    if source is None:
        return UPSTREAM_DATA_SOURCES
    return (source,)


def _resolve_upstream_source(
    source: FingerprintDataSource,
    *,
    repo: str | None,
    ref: str | None,
) -> UpstreamSource:
    defaults = UPSTREAM_SOURCES[source]
    return UpstreamSource(
        source=source,
        repo=repo or defaults.repo,
        ref=ref or defaults.ref,
    )


def _override_dataset_paths(
    paths: SyncPaths,
    source: FingerprintDataSource,
    *,
    fingerprints: Path | None = None,
    categories: Path | None = None,
) -> SyncPaths:
    updated = dict(paths.datasets)
    current = updated[source]
    updated[source] = DatasetPaths(
        fingerprints=fingerprints or current.fingerprints,
        categories=categories or current.categories,
    )
    return SyncPaths(datasets=updated, metadata=paths.metadata)


def _build_metadata(
    *,
    source_results: Mapping[FingerprintDataSource, SourceSyncResult],
    comparison_input: Mapping[
        FingerprintDataSource, tuple[NormalizedApps, NormalizedCategories]
    ],
    fetched_at_utc: str,
    anti_bot_technologies_count: int,
    anti_bot_technologies_source: str,
    anti_bot_vendor_aliases_count: int,
    anti_bot_product_aliases_count: int,
) -> dict[str, object]:
    sources_metadata: dict[str, object] = {}
    for source in sorted(source_results, key=lambda item: item.value):
        result = source_results[source]
        source_metadata: dict[str, object] = {
            "counts": {
                "technologies": result.technologies,
                "categories": result.categories,
                "technology_files": len(TECHNOLOGY_FILE_STEMS),
            }
        }
        if source is FingerprintDataSource.MERGED:
            source_metadata["generated_from"] = [
                FingerprintDataSource.ENTHEC.value,
                FingerprintDataSource.HTTPARCHIVE.value,
            ]
            source_metadata["fetched_at_utc"] = fetched_at_utc
        else:
            source_metadata["repo"] = result.repo
            source_metadata["ref"] = result.ref
            source_metadata["commit"] = result.commit
            source_metadata["fetched_at_utc"] = fetched_at_utc
        sources_metadata[source.value] = source_metadata

    return {
        "default_source": DEFAULT_FINGERPRINT_DATA_SOURCE.value,
        "anti_bot_technologies": {
            "count": anti_bot_technologies_count,
            "derived_from": anti_bot_technologies_source,
        },
        "anti_bot_aliases": {
            "vendor_aliases": anti_bot_vendor_aliases_count,
            "product_aliases": anti_bot_product_aliases_count,
        },
        "anti_bot_rule_set": _build_curated_rule_set_metadata(),
        "sources": sources_metadata,
        "comparison": _build_comparison(comparison_input),
    }


def _build_curated_rule_set_metadata() -> dict[str, object]:
    data_dir = Path(__file__).resolve().parent / "data" / "antibot"
    files: dict[str, object] = {}
    for filename in CURATED_ANTI_BOT_RULE_FILES:
        path = data_dir / filename
        payload_text = path.read_text(encoding="utf-8")
        payload = json.loads(payload_text)
        files[filename] = {
            "sha256": hashlib.sha256(payload_text.encode("utf-8")).hexdigest(),
            **_curated_rule_file_counts(filename, payload),
        }
    return {
        "path": "src/wappalyzer_pure/data/antibot",
        "files": files,
    }


def _curated_rule_file_counts(
    filename: str,
    payload: object,
) -> dict[str, int]:
    if not isinstance(payload, Mapping):
        raise TypeError(
            f"curated anti-bot rule file must contain a mapping: {filename}"
        )
    mapping_payload = cast(Mapping[str, object], payload)

    if filename == "anti_bot_signals_data.json":
        vendors = mapping_payload.get("vendors", [])
        if not isinstance(vendors, list):
            raise TypeError("anti_bot_signals_data.json vendors must be a list")
        behavior_count = 0
        for vendor in vendors:
            if not isinstance(vendor, Mapping):
                continue
            vendor_mapping = cast(Mapping[str, object], vendor)
            behaviors = vendor_mapping.get("behaviors", [])
            if isinstance(behaviors, list):
                behavior_count += len(behaviors)
        return {
            "vendor_count": len(vendors),
            "behavior_count": behavior_count,
        }

    if filename == "anti_bot_catalog_rules.json":
        behavior_keywords = mapping_payload.get("behavior_keywords", {})
        if not isinstance(behavior_keywords, Mapping):
            raise TypeError(
                "anti_bot_catalog_rules.json behavior_keywords must be a mapping"
            )
        keyword_count = 0
        for keywords in behavior_keywords.values():
            if isinstance(keywords, list):
                keyword_count += len(keywords)
        return {
            "behavior_group_count": len(behavior_keywords),
            "keyword_count": keyword_count,
        }

    if filename == "anti_bot_alias_rules.json":
        vendors = mapping_payload.get("vendors", [])
        products = mapping_payload.get("products", [])
        if not isinstance(vendors, list):
            raise TypeError("anti_bot_alias_rules.json vendors must be a list")
        if not isinstance(products, list):
            raise TypeError("anti_bot_alias_rules.json products must be a list")
        return {
            "vendor_alias_group_count": len(vendors),
            "product_alias_group_count": len(products),
        }

    raise ValueError(f"unsupported curated anti-bot rule file: {filename}")


def _build_merged_dataset(
    comparison_input: Mapping[
        FingerprintDataSource, tuple[NormalizedApps, NormalizedCategories]
    ],
) -> tuple[NormalizedApps, NormalizedCategories]:
    primary_apps, primary_categories = comparison_input[FingerprintDataSource.ENTHEC]
    secondary_apps, secondary_categories = comparison_input[
        FingerprintDataSource.HTTPARCHIVE
    ]
    merged_apps: NormalizedApps = {}
    for name in sorted(set(primary_apps) | set(secondary_apps), key=str.casefold):
        primary_value = primary_apps.get(name)
        secondary_value = secondary_apps.get(name)
        if primary_value is None:
            merged_apps[name] = dict(secondary_value or {})
            continue
        if secondary_value is None:
            merged_apps[name] = dict(primary_value)
            continue
        merged_apps[name] = cast(
            dict[str, object],
            _merge_normalized_value(primary_value, secondary_value),
        )

    merged_categories: NormalizedCategories = {}
    for key in sorted(
        set(primary_categories) | set(secondary_categories),
        key=lambda value: int(value),
    ):
        primary_value = primary_categories.get(key)
        secondary_value = secondary_categories.get(key)
        if primary_value is None:
            merged_categories[key] = secondary_value
            continue
        if secondary_value is None:
            merged_categories[key] = primary_value
            continue
        merged_categories[key] = _merge_normalized_value(primary_value, secondary_value)

    return merged_apps, merged_categories


def _build_comparison(
    comparison_input: Mapping[
        FingerprintDataSource, tuple[NormalizedApps, NormalizedCategories]
    ],
) -> dict[str, object]:
    if len(comparison_input) < 2:
        return {}

    left = FingerprintDataSource.ENTHEC
    right = FingerprintDataSource.HTTPARCHIVE
    if left not in comparison_input or right not in comparison_input:
        return {}

    left_apps, left_categories = comparison_input[left]
    right_apps, right_categories = comparison_input[right]

    left_app_names = set(left_apps)
    right_app_names = set(right_apps)
    shared_app_names = left_app_names & right_app_names
    identical_apps = sum(
        1 for name in shared_app_names if left_apps[name] == right_apps[name]
    )

    left_category_names = set(left_categories)
    right_category_names = set(right_categories)
    shared_category_names = left_category_names & right_category_names
    identical_categories = sum(
        1
        for name in shared_category_names
        if left_categories[name] == right_categories[name]
    )

    return {
        "technologies": {
            "shared": len(shared_app_names),
            f"only_{left.value}": len(left_app_names - right_app_names),
            f"only_{right.value}": len(right_app_names - left_app_names),
            "identical_shared": identical_apps,
            "different_shared": len(shared_app_names) - identical_apps,
        },
        "categories": {
            "shared": len(shared_category_names),
            f"only_{left.value}": len(left_category_names - right_category_names),
            f"only_{right.value}": len(right_category_names - left_category_names),
            "identical_shared": identical_categories,
            "different_shared": len(shared_category_names) - identical_categories,
        },
    }


def _merge_normalized_value(primary: object, secondary: object) -> object:
    if isinstance(primary, Mapping) and isinstance(secondary, Mapping):
        primary_mapping = cast(Mapping[str, object], primary)
        secondary_mapping = cast(Mapping[str, object], secondary)
        merged: dict[str, object] = {}
        keys = sorted(
            set(primary_mapping) | set(secondary_mapping),
            key=str.casefold,
        )
        for key in keys:
            primary_value = primary_mapping.get(key)
            secondary_value = secondary_mapping.get(key)
            if primary_value is None:
                merged[key] = secondary_value
                continue
            if secondary_value is None:
                merged[key] = primary_value
                continue
            merged[key] = _merge_normalized_value(primary_value, secondary_value)
        return merged

    if isinstance(primary, list) and isinstance(secondary, list):
        merged_list: list[object] = []
        seen: set[str] = set()
        for item in [*primary, *secondary]:
            marker = json.dumps(item, sort_keys=True)
            if marker in seen:
                continue
            seen.add(marker)
            merged_list.append(item)
        return merged_list

    if primary in (None, "", [], {}):
        return secondary
    return primary


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
