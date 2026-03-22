from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, cast
from urllib import parse as urllib_parse

from .exceptions import DataLoadError


@dataclass(frozen=True, slots=True)
class AntiBotTechnologyCatalogEntry:
    name: str
    vendor: str
    behaviors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "vendor": self.vendor,
            "behaviors": list(self.behaviors),
        }


@dataclass(frozen=True, slots=True)
class _CatalogRules:
    behavior_keywords: Mapping[str, tuple[str, ...]]


def anti_bot_technologies_filename() -> str:
    return "anti_bot_technologies_data.json"


def anti_bot_catalog_rules_filename() -> str:
    return "anti_bot_catalog_rules.json"


def derive_anti_bot_technology_catalog(
    apps: Mapping[str, Mapping[str, object]],
    categories: Mapping[Any, Any],
) -> dict[str, AntiBotTechnologyCatalogEntry]:
    category_lookup = _category_name_lookup(categories)
    rules = load_anti_bot_catalog_rules()
    seeded_hints = _seeded_technology_hints()
    catalog: dict[str, AntiBotTechnologyCatalogEntry] = {}

    for name, payload in sorted(apps.items(), key=lambda item: item[0].casefold()):
        behaviors = set(
            _derive_behaviors(
                name=name,
                payload=payload,
                category_lookup=category_lookup,
                rules=rules,
            )
        )
        seeded_hint = seeded_hints.get(name.casefold())
        vendor = seeded_hint.vendor if seeded_hint is not None else name
        if seeded_hint is not None:
            behaviors.update(seeded_hint.behaviors)

        if not behaviors and seeded_hint is None:
            continue

        catalog[name.casefold()] = AntiBotTechnologyCatalogEntry(
            name=name,
            vendor=vendor,
            behaviors=tuple(sorted(behaviors)),
        )

    return catalog


@lru_cache
def load_packaged_anti_bot_technology_catalog(
    *,
    package: str = "wappalyzer_pure.data",
) -> dict[str, AntiBotTechnologyCatalogEntry]:
    try:
        payload = json.loads(
            resources.files(package)
            .joinpath(f"antibot/{anti_bot_technologies_filename()}")
            .read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise DataLoadError(
            f"failed to decode anti-bot technology data: {exc}"
        ) from exc

    mapping = payload.get("technologies")
    if not isinstance(mapping, dict):
        raise DataLoadError("anti-bot technology data is missing the technologies map")

    result: dict[str, AntiBotTechnologyCatalogEntry] = {}
    for key, value in mapping.items():
        if not isinstance(key, str) or not key:
            raise DataLoadError(
                f"anti-bot technology keys must be non-empty strings, got {key!r}"
            )
        if not isinstance(value, Mapping):
            raise DataLoadError(
                f"anti-bot technology entry must be a mapping, got {value!r}"
            )
        name = value.get("name")
        vendor = value.get("vendor")
        behaviors = value.get("behaviors", [])
        if not isinstance(name, str) or not name:
            raise DataLoadError(
                f"anti-bot technology name must be a non-empty string, got {name!r}"
            )
        if not isinstance(vendor, str) or not vendor:
            raise DataLoadError(
                f"anti-bot technology vendor must be a non-empty string, got {vendor!r}"
            )
        if not isinstance(behaviors, list) or not all(
            isinstance(item, str) and item for item in behaviors
        ):
            raise DataLoadError(
                f"anti-bot technology behaviors must be a list of strings, got {behaviors!r}"
            )
        result[key.casefold()] = AntiBotTechnologyCatalogEntry(
            name=name,
            vendor=vendor,
            behaviors=tuple(sorted(set(behaviors))),
        )
    return result


def serialize_anti_bot_technology_catalog(
    catalog: Mapping[str, AntiBotTechnologyCatalogEntry],
) -> dict[str, object]:
    return {
        "technologies": {
            key: value.to_dict()
            for key, value in sorted(catalog.items(), key=lambda item: item[0])
        }
    }


def _category_name_lookup(categories: Mapping[Any, Any]) -> dict[int, str]:
    lookup: dict[int, str] = {}
    for key, value in categories.items():
        if not isinstance(key, (int, str)):
            continue
        category_id = int(key)
        if isinstance(value, Mapping):
            mapping_value = cast(Mapping[str, object], value)
            name = mapping_value.get("name")
            if isinstance(name, str) and name:
                lookup[category_id] = name
            continue
        name = getattr(value, "name", None)
        if isinstance(name, str) and name:
            lookup[category_id] = name
    return lookup


def _derive_behaviors(
    *,
    name: str,
    payload: Mapping[str, object],
    category_lookup: Mapping[int, str],
    rules: _CatalogRules,
) -> tuple[str, ...]:
    haystacks = [name.casefold()]
    description = payload.get("description")
    website = payload.get("website")
    if isinstance(description, str) and description:
        haystacks.append(description.casefold())
    if isinstance(website, str) and website:
        haystacks.append(website.casefold())
        domain = _domain_label(website)
        if domain is not None:
            haystacks.append(domain)

    category_ids = payload.get("cats", [])
    if isinstance(category_ids, list):
        for item in category_ids:
            if isinstance(item, int):
                category_name = category_lookup.get(item)
                if category_name:
                    haystacks.append(category_name.casefold())

    behaviors: list[str] = []
    for behavior_name, keywords in rules.behavior_keywords.items():
        if _contains_keyword(haystacks, keywords):
            behaviors.append(behavior_name)
    return tuple(behaviors)


def _contains_keyword(haystacks: list[str], keywords: tuple[str, ...]) -> bool:
    return any(keyword in text for text in haystacks for keyword in keywords)


def _domain_label(url: str) -> str | None:
    hostname = urllib_parse.urlsplit(url).hostname
    if not hostname:
        return None
    parts = hostname.casefold().split(".")
    if len(parts) < 2:
        return parts[0]
    return re.sub(r"[^a-z0-9]+", "", parts[-2])


@lru_cache
def _seeded_technology_hints() -> dict[str, AntiBotTechnologyCatalogEntry]:
    package = "wappalyzer_pure.data"
    try:
        payload = json.loads(
            resources.files(package)
            .joinpath("antibot/anti_bot_signals_data.json")
            .read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise DataLoadError(f"failed to decode anti-bot signal data: {exc}") from exc

    vendors = payload.get("vendors")
    if not isinstance(vendors, list):
        raise DataLoadError("anti-bot signal data is missing the vendors list")

    hints: dict[str, AntiBotTechnologyCatalogEntry] = {}
    for raw_vendor in vendors:
        if not isinstance(raw_vendor, Mapping):
            continue
        vendor_name = raw_vendor.get("name")
        if not isinstance(vendor_name, str) or not vendor_name:
            continue

        vendor_signals = raw_vendor.get("signals")
        if isinstance(vendor_signals, Mapping):
            for technology_name in _technology_names_from_signals(vendor_signals):
                hints.setdefault(
                    technology_name.casefold(),
                    AntiBotTechnologyCatalogEntry(
                        name=technology_name,
                        vendor=vendor_name,
                        behaviors=(),
                    ),
                )

        behaviors = raw_vendor.get("behaviors", [])
        if not isinstance(behaviors, list):
            continue
        for raw_behavior in behaviors:
            if not isinstance(raw_behavior, Mapping):
                continue
            behavior_name = raw_behavior.get("name")
            signals = raw_behavior.get("signals")
            if not isinstance(behavior_name, str) or not behavior_name:
                continue
            if not isinstance(signals, Mapping):
                continue
            for technology_name in _technology_names_from_signals(signals):
                marker = technology_name.casefold()
                existing = hints.get(marker)
                existing_behaviors = set(() if existing is None else existing.behaviors)
                existing_behaviors.add(behavior_name)
                hints[marker] = AntiBotTechnologyCatalogEntry(
                    name=technology_name,
                    vendor=vendor_name if existing is None else existing.vendor,
                    behaviors=tuple(sorted(existing_behaviors)),
                )

    return hints


def _technology_names_from_signals(signals: Mapping[object, object]) -> tuple[str, ...]:
    raw_names = signals.get("technology_names")
    if not isinstance(raw_names, list):
        return ()
    names: list[str] = []
    for value in raw_names:
        if not isinstance(value, str) or not value:
            continue
        names.append(value)
    return tuple(names)


@lru_cache
def load_anti_bot_catalog_rules(
    *,
    package: str = "wappalyzer_pure.data",
) -> _CatalogRules:
    try:
        payload = json.loads(
            resources.files(package)
            .joinpath(f"antibot/{anti_bot_catalog_rules_filename()}")
            .read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise DataLoadError(f"failed to decode anti-bot catalog rules: {exc}") from exc

    behavior_keywords_payload = payload.get("behavior_keywords")
    if not isinstance(behavior_keywords_payload, Mapping):
        raise DataLoadError(
            "anti-bot catalog rules are missing the behavior_keywords mapping"
        )

    behavior_keywords: dict[str, tuple[str, ...]] = {}
    for behavior_name, keywords in behavior_keywords_payload.items():
        if not isinstance(behavior_name, str) or not behavior_name:
            raise DataLoadError(
                f"anti-bot behavior names must be non-empty strings, got {behavior_name!r}"
            )
        if not isinstance(keywords, list) or not all(
            isinstance(item, str) and item for item in keywords
        ):
            raise DataLoadError(
                f"anti-bot behavior keywords must be a list of strings, got {keywords!r}"
            )
        behavior_keywords[behavior_name] = tuple(item.casefold() for item in keywords)

    return _CatalogRules(behavior_keywords=behavior_keywords)
