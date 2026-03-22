from __future__ import annotations

from wappalyzer_pure.antibot_catalog import (
    derive_anti_bot_technology_catalog,
    load_anti_bot_catalog_rules,
    load_packaged_anti_bot_technology_catalog,
)


def test_load_anti_bot_catalog_rules_from_packaged_json() -> None:
    rules = load_anti_bot_catalog_rules()

    assert "captcha" in rules.behavior_keywords
    assert "turnstile" in rules.behavior_keywords["captcha"]
    assert "bot_management" in rules.behavior_keywords
    assert "scraping" in rules.behavior_keywords["bot_management"]


def test_load_packaged_anti_bot_technology_catalog_contains_generated_entries() -> None:
    catalog = load_packaged_anti_bot_technology_catalog()

    assert "cloudflare bot management" in catalog
    assert catalog["cloudflare bot management"].vendor == "Cloudflare"
    assert "bot_management" in catalog["cloudflare bot management"].behaviors


def test_derive_anti_bot_technology_catalog_respects_seeded_vendor_hints() -> None:
    catalog = derive_anti_bot_technology_catalog(
        {
            "Cloudflare Turnstile": {
                "cats": [16],
                "description": "Turnstile is Cloudflare's smart CAPTCHA alternative.",
                "website": "https://www.cloudflare.com/products/turnstile/",
            }
        },
        {
            "16": {"name": "Security", "priority": 1},
        },
    )

    assert catalog["cloudflare turnstile"].vendor == "Cloudflare"
    assert catalog["cloudflare turnstile"].behaviors == ("captcha",)
