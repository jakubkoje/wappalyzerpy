from __future__ import annotations

from wappalyzer_pure.antibot_aliases import (
    CanonicalProductAlias,
    derive_anti_bot_alias_catalog,
    load_anti_bot_alias_rules,
    load_packaged_anti_bot_alias_catalog,
)
from wappalyzer_pure.antibot_catalog import AntiBotTechnologyCatalogEntry


def test_load_anti_bot_alias_rules_from_packaged_json() -> None:
    rules = load_anti_bot_alias_rules()

    assert any(rule.canonical_name == "HUMAN" for rule in rules.vendors)
    human_rule = next(rule for rule in rules.vendors if rule.canonical_name == "HUMAN")
    assert "HUMAN / PerimeterX" in human_rule.aliases

    turnstile_rule = next(
        rule for rule in rules.products if rule.canonical_name == "Cloudflare Turnstile"
    )
    assert "Turnstile" in turnstile_rule.aliases


def test_derive_anti_bot_alias_catalog_canonicalizes_vendor_and_product_aliases() -> (
    None
):
    catalog = derive_anti_bot_alias_catalog(
        {
            "akamai bot manager": AntiBotTechnologyCatalogEntry(
                name="Akamai Bot Manager",
                vendor="Akamai Bot Manager",
                behaviors=("bot_management",),
            ),
            "friendly captcha": AntiBotTechnologyCatalogEntry(
                name="Friendly Captcha",
                vendor="Friendly Captcha",
                behaviors=("captcha",),
            ),
            "perimeterx": AntiBotTechnologyCatalogEntry(
                name="PerimeterX",
                vendor="HUMAN / PerimeterX",
                behaviors=(),
            ),
        }
    )

    assert catalog.canonical_vendor_name("Akamai Bot Manager") == "Akamai"
    assert catalog.canonical_vendor_name("HUMAN / PerimeterX") == "HUMAN"
    assert catalog.canonicalize_product(
        "PerimeterX",
        vendor="HUMAN / PerimeterX",
    ) == CanonicalProductAlias(
        canonical_name="PerimeterX",
        canonical_vendor="HUMAN",
    )
    assert catalog.canonicalize_product(
        "Friendly Captcha",
        vendor="Friendly Captcha",
    ) == CanonicalProductAlias(
        canonical_name="Friendly Captcha",
        canonical_vendor="Friendly Captcha",
    )


def test_load_packaged_anti_bot_alias_catalog_contains_generated_entries() -> None:
    catalog = load_packaged_anti_bot_alias_catalog()

    assert catalog.canonical_vendor_name("Akamai Bot Manager") == "Akamai"
    assert catalog.canonical_vendor_name("HUMAN / PerimeterX") == "HUMAN"
    assert catalog.canonicalize_product(
        "Cloudflare Turnstile",
        vendor="Cloudflare",
    ) == CanonicalProductAlias(
        canonical_name="Cloudflare Turnstile",
        canonical_vendor="Cloudflare",
    )
