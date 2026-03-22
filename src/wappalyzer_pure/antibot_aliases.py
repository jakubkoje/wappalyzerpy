from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from .antibot_catalog import AntiBotTechnologyCatalogEntry
from .exceptions import DataLoadError


@dataclass(frozen=True, slots=True)
class CanonicalProductAlias:
    canonical_name: str
    canonical_vendor: str

    def to_dict(self) -> dict[str, str]:
        return {
            "canonical_name": self.canonical_name,
            "canonical_vendor": self.canonical_vendor,
        }


@dataclass(frozen=True, slots=True)
class AntiBotAliasCatalog:
    vendor_aliases: Mapping[str, str]
    product_aliases: Mapping[str, CanonicalProductAlias]

    def canonical_vendor_name(self, name: str) -> str:
        return self.vendor_aliases.get(name.casefold(), name)

    def canonicalize_product(
        self,
        name: str,
        *,
        vendor: str,
    ) -> CanonicalProductAlias:
        entry = self.product_aliases.get(name.casefold())
        if entry is not None:
            return entry
        return CanonicalProductAlias(
            canonical_name=name,
            canonical_vendor=self.canonical_vendor_name(vendor),
        )


@dataclass(frozen=True, slots=True)
class _VendorAliasRule:
    canonical_name: str
    aliases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ProductAliasRule:
    canonical_name: str
    canonical_vendor: str
    aliases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _AliasRules:
    vendors: tuple[_VendorAliasRule, ...]
    products: tuple[_ProductAliasRule, ...]


def anti_bot_aliases_filename() -> str:
    return "anti_bot_aliases_data.json"


def anti_bot_alias_rules_filename() -> str:
    return "anti_bot_alias_rules.json"


def derive_anti_bot_alias_catalog(
    anti_bot_catalog: Mapping[str, AntiBotTechnologyCatalogEntry],
) -> AntiBotAliasCatalog:
    rules = load_anti_bot_alias_rules()
    vendor_aliases: dict[str, str] = {}
    product_aliases: dict[str, CanonicalProductAlias] = {}

    for rule in rules.vendors:
        _register_vendor_aliases(
            vendor_aliases,
            canonical_name=rule.canonical_name,
            aliases=(rule.canonical_name, *rule.aliases),
        )

    for rule in rules.products:
        canonical_vendor = vendor_aliases.get(
            rule.canonical_vendor.casefold(),
            rule.canonical_vendor,
        )
        entry = CanonicalProductAlias(
            canonical_name=rule.canonical_name,
            canonical_vendor=canonical_vendor,
        )
        for alias in (rule.canonical_name, *rule.aliases):
            product_aliases[alias.casefold()] = entry

    for key, entry in sorted(anti_bot_catalog.items(), key=lambda item: item[0]):
        canonical_vendor = vendor_aliases.get(entry.vendor.casefold(), entry.vendor)
        _register_vendor_aliases(
            vendor_aliases,
            canonical_name=canonical_vendor,
            aliases=(entry.vendor, canonical_vendor),
        )

        product_entry = product_aliases.get(entry.name.casefold())
        if product_entry is None:
            product_entry = CanonicalProductAlias(
                canonical_name=entry.name,
                canonical_vendor=canonical_vendor,
            )
        else:
            product_entry = CanonicalProductAlias(
                canonical_name=product_entry.canonical_name,
                canonical_vendor=vendor_aliases.get(
                    product_entry.canonical_vendor.casefold(),
                    product_entry.canonical_vendor,
                ),
            )

        product_aliases.setdefault(key.casefold(), product_entry)
        product_aliases.setdefault(entry.name.casefold(), product_entry)

    return AntiBotAliasCatalog(
        vendor_aliases={
            key: value
            for key, value in sorted(vendor_aliases.items(), key=lambda item: item[0])
        },
        product_aliases={
            key: value
            for key, value in sorted(product_aliases.items(), key=lambda item: item[0])
        },
    )


@lru_cache
def load_anti_bot_alias_rules(
    *,
    package: str = "wappalyzer_pure.data",
) -> _AliasRules:
    try:
        payload = json.loads(
            resources.files(package)
            .joinpath(f"antibot/{anti_bot_alias_rules_filename()}")
            .read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise DataLoadError(f"failed to decode anti-bot alias rules: {exc}") from exc

    if not isinstance(payload, Mapping):
        raise DataLoadError("anti-bot alias rules must be a mapping")

    vendors_payload = payload.get("vendors", [])
    products_payload = payload.get("products", [])
    if not isinstance(vendors_payload, list):
        raise DataLoadError("anti-bot alias rules vendors must be a list")
    if not isinstance(products_payload, list):
        raise DataLoadError("anti-bot alias rules products must be a list")

    return _AliasRules(
        vendors=tuple(_parse_vendor_alias_rule(item) for item in vendors_payload),
        products=tuple(_parse_product_alias_rule(item) for item in products_payload),
    )


@lru_cache
def load_packaged_anti_bot_alias_catalog(
    *,
    package: str = "wappalyzer_pure.data",
) -> AntiBotAliasCatalog:
    try:
        payload = json.loads(
            resources.files(package)
            .joinpath(f"antibot/{anti_bot_aliases_filename()}")
            .read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        from .antibot_catalog import load_packaged_anti_bot_technology_catalog

        return derive_anti_bot_alias_catalog(
            load_packaged_anti_bot_technology_catalog(package=package)
        )
    except json.JSONDecodeError as exc:
        raise DataLoadError(f"failed to decode anti-bot alias data: {exc}") from exc

    if not isinstance(payload, Mapping):
        raise DataLoadError("anti-bot alias data must be a mapping")

    vendors_payload = payload.get("vendors")
    products_payload = payload.get("products")
    if not isinstance(vendors_payload, Mapping):
        raise DataLoadError("anti-bot alias data is missing the vendors mapping")
    if not isinstance(products_payload, Mapping):
        raise DataLoadError("anti-bot alias data is missing the products mapping")

    vendor_aliases: dict[str, str] = {}
    for key, value in vendors_payload.items():
        if not isinstance(key, str) or not key:
            raise DataLoadError(
                f"anti-bot vendor alias keys must be non-empty strings, got {key!r}"
            )
        if not isinstance(value, str) or not value:
            raise DataLoadError(
                f"anti-bot vendor alias values must be non-empty strings, got {value!r}"
            )
        vendor_aliases[key.casefold()] = value

    product_aliases: dict[str, CanonicalProductAlias] = {}
    for key, value in products_payload.items():
        if not isinstance(key, str) or not key:
            raise DataLoadError(
                f"anti-bot product alias keys must be non-empty strings, got {key!r}"
            )
        if not isinstance(value, Mapping):
            raise DataLoadError(
                f"anti-bot product alias values must be mappings, got {value!r}"
            )
        canonical_name = value.get("canonical_name")
        canonical_vendor = value.get("canonical_vendor")
        if not isinstance(canonical_name, str) or not canonical_name:
            raise DataLoadError(
                "anti-bot product canonical_name must be a non-empty string"
            )
        if not isinstance(canonical_vendor, str) or not canonical_vendor:
            raise DataLoadError(
                "anti-bot product canonical_vendor must be a non-empty string"
            )
        product_aliases[key.casefold()] = CanonicalProductAlias(
            canonical_name=canonical_name,
            canonical_vendor=canonical_vendor,
        )

    return AntiBotAliasCatalog(
        vendor_aliases=vendor_aliases,
        product_aliases=product_aliases,
    )


def serialize_anti_bot_alias_catalog(
    catalog: AntiBotAliasCatalog,
) -> dict[str, object]:
    return {
        "vendors": {
            key: value
            for key, value in sorted(
                catalog.vendor_aliases.items(),
                key=lambda item: item[0],
            )
        },
        "products": {
            key: value.to_dict()
            for key, value in sorted(
                catalog.product_aliases.items(),
                key=lambda item: item[0],
            )
        },
    }


def _register_vendor_aliases(
    mapping: dict[str, str],
    *,
    canonical_name: str,
    aliases: tuple[str, ...],
) -> None:
    for alias in aliases:
        mapping[alias.casefold()] = canonical_name


def _parse_vendor_alias_rule(value: object) -> _VendorAliasRule:
    mapping = _ensure_string_mapping(value, label="anti-bot vendor alias rule")
    canonical_name = _require_non_empty_string(
        mapping.get("canonical_name"),
        field="canonical_name",
    )
    return _VendorAliasRule(
        canonical_name=canonical_name,
        aliases=_parse_alias_list(mapping.get("aliases")),
    )


def _parse_product_alias_rule(value: object) -> _ProductAliasRule:
    mapping = _ensure_string_mapping(value, label="anti-bot product alias rule")
    canonical_name = _require_non_empty_string(
        mapping.get("canonical_name"),
        field="canonical_name",
    )
    canonical_vendor = _require_non_empty_string(
        mapping.get("canonical_vendor"),
        field="canonical_vendor",
    )
    return _ProductAliasRule(
        canonical_name=canonical_name,
        canonical_vendor=canonical_vendor,
        aliases=_parse_alias_list(mapping.get("aliases")),
    )


def _parse_alias_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise DataLoadError(f"anti-bot aliases must be a list, got {value!r}")
    aliases: list[str] = []
    for item in value:
        aliases.append(_require_non_empty_string(item, field="alias"))
    return tuple(aliases)


def _require_non_empty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise DataLoadError(
            f"anti-bot {field} must be a non-empty string, got {value!r}"
        )
    return value


def _ensure_string_mapping(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DataLoadError(f"{label} must be a mapping, got {value!r}")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise DataLoadError(f"{label} keys must be strings, got {key!r}")
        result[key] = item
    return result
