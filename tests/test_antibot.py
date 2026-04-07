from __future__ import annotations

from wappalyzer_pure.antibot import inspect_anti_bot_findings
from wappalyzer_pure.antibot_aliases import derive_anti_bot_alias_catalog
from wappalyzer_pure.antibot_catalog import AntiBotTechnologyCatalogEntry
from wappalyzer_pure.models import AntiBotEvidence, Technology


def test_inspect_anti_bot_findings_ignores_generic_security_vendor_presence() -> None:
    findings = inspect_anti_bot_findings(
        headers={"Server": ["cloudflare"], "CF-Ray": ["trace"]},
        body=b"<html></html>",
        technologies=(
            Technology(
                raw_name="Cloudflare",
                name="Cloudflare",
                categories=("CDN",),
                security_relevant=True,
            ),
        ),
    )

    assert findings == ()


def test_inspect_anti_bot_findings_detects_cloudflare_challenge_page() -> None:
    findings = inspect_anti_bot_findings(
        headers={"Server": ["cloudflare"], "CF-Ray": ["trace"]},
        body=b"<html>Just a moment... /cdn-cgi/challenge-platform/</html>",
        technologies=(),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Cloudflare"
    assert finding.score == 8
    assert finding.confidence == "high"
    assert "challenge" in finding.behaviors


def test_inspect_anti_bot_findings_supports_cookie_prefix_rules() -> None:
    findings = inspect_anti_bot_findings(
        headers={"Set-Cookie": ["nlbi_123456=abc; Path=/; HttpOnly"]},
        body=b"<html></html>",
        technologies=(),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Imperva"
    assert finding.score == 3
    assert finding.behaviors == ("session_enforcement",)
    assert finding.evidence[0].matched_value == "nlbi_123456"
    assert finding.evidence[0].artifact == "nlbi_123456=abc; Path=/; HttpOnly"


def test_inspect_anti_bot_findings_can_match_multiple_behaviors() -> None:
    findings = inspect_anti_bot_findings(
        headers={
            "Server": ["cloudflare"],
            "Set-Cookie": ["__cf_bm=opaque; Path=/; HttpOnly"],
        },
        body=b"<html>Just a moment... /cdn-cgi/challenge-platform/</html>",
        technologies=(),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Cloudflare"
    assert finding.score == 10
    assert finding.confidence == "high"
    assert finding.behaviors == ("bot_management", "challenge")


def test_inspect_anti_bot_findings_can_match_script_source_signals() -> None:
    findings = inspect_anti_bot_findings(
        headers={"Server": ["cloudflare"]},
        body=b"<html></html>",
        technologies=(),
        script_sources=("https://challenges.cloudflare.com/turnstile/v0/api.js",),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Cloudflare"
    assert finding.score == 4
    assert finding.behaviors == ("captcha",)
    assert any(item.source == "script_source" for item in finding.evidence)


def test_inspect_anti_bot_findings_can_match_script_content_signals() -> None:
    findings = inspect_anti_bot_findings(
        headers={},
        body=b"<html></html>",
        technologies=(),
        script_contents=("window.kpsdk = { version: '1.0' };",),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Kasada"
    assert finding.score == 3
    assert finding.behaviors == ("bot_management",)
    assert any(item.source == "script_content" for item in finding.evidence)


def test_inspect_anti_bot_findings_matches_technology_names_from_signal_rules() -> None:
    findings = inspect_anti_bot_findings(
        headers={},
        body=b"<html></html>",
        technologies=(
            Technology(
                raw_name="HUMAN Security",
                name="HUMAN Security",
                categories=("Security",),
                security_relevant=True,
            ),
        ),
        anti_bot_aliases=derive_anti_bot_alias_catalog({}),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "HUMAN"
    assert finding.score == 3
    assert finding.confidence == "medium"
    assert finding.evidence == (
        AntiBotEvidence(
            source="technology",
            indicator="human security",
            matched_value="HUMAN Security",
            artifact="HUMAN Security",
        ),
    )


def test_inspect_anti_bot_findings_can_infer_recaptcha_from_security_headers() -> None:
    anti_bot_catalog = {
        "recaptcha": AntiBotTechnologyCatalogEntry(
            name="reCAPTCHA",
            vendor="reCAPTCHA",
            behaviors=("captcha",),
        )
    }
    findings = inspect_anti_bot_findings(
        headers={
            "Content-Security-Policy": [
                "default-src 'self'; frame-src https://www.google.com/recaptcha/;"
            ]
        },
        body=b"",
        technologies=(),
        anti_bot_catalog=anti_bot_catalog,
        anti_bot_aliases=derive_anti_bot_alias_catalog(anti_bot_catalog),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "reCAPTCHA"
    assert finding.score == 3
    assert finding.confidence == "medium"
    assert finding.products == ("reCAPTCHA",)
    assert finding.behaviors == ("captcha",)
    assert finding.evidence == (
        AntiBotEvidence(
            source="security_header",
            indicator="content-security-policy",
            matched_value="www.google.com/recaptcha",
            artifact=(
                "content-security-policy: default-src 'self'; frame-src "
                "https://www.google.com/recaptcha/;"
            ),
        ),
    )


def test_inspect_anti_bot_findings_can_infer_perimeterx_from_csp_and_inline_bootstrap() -> (
    None
):
    anti_bot_catalog = {
        "perimeterx": AntiBotTechnologyCatalogEntry(
            name="PerimeterX",
            vendor="HUMAN / PerimeterX",
            behaviors=("bot_management",),
        )
    }
    findings = inspect_anti_bot_findings(
        headers={
            "Content-Security-Policy": [
                "script-src 'self' https://*.px-cdn.net https://*.px-cloud.net"
            ]
        },
        body=b"<script>window._pxAppId='PXu6b0qd2S';</script>",
        technologies=(),
        anti_bot_catalog=anti_bot_catalog,
        anti_bot_aliases=derive_anti_bot_alias_catalog(anti_bot_catalog),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "HUMAN"
    assert finding.products == ("PerimeterX",)
    assert finding.behaviors == ("bot_management",)
    assert {item.source for item in finding.evidence} == {"body", "security_header"}


def test_inspect_anti_bot_findings_canonicalizes_vendor_aliases_from_signal_rules() -> (
    None
):
    findings = inspect_anti_bot_findings(
        headers={"Set-Cookie": ["_abck=opaque; Path=/; HttpOnly"]},
        body=b"<html></html>",
        technologies=(),
        anti_bot_aliases=derive_anti_bot_alias_catalog({}),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Akamai"
    assert finding.products == ()
    assert finding.behaviors == ("bot_management",)


def test_inspect_anti_bot_findings_can_derive_findings_from_detected_technology() -> (
    None
):
    anti_bot_catalog = {
        "friendly captcha": AntiBotTechnologyCatalogEntry(
            name="Friendly Captcha",
            vendor="Friendly Captcha",
            behaviors=("captcha",),
        )
    }
    findings = inspect_anti_bot_findings(
        headers={},
        body=b"<html></html>",
        technologies=(
            Technology(
                raw_name="Friendly Captcha",
                name="Friendly Captcha",
                description="Friendly Captcha is a privacy-friendly CAPTCHA alternative.",
                categories=("Security",),
                security_relevant=True,
            ),
        ),
        anti_bot_catalog=anti_bot_catalog,
        anti_bot_aliases=derive_anti_bot_alias_catalog(anti_bot_catalog),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Friendly Captcha"
    assert finding.score == 3
    assert finding.confidence == "medium"
    assert finding.products == ("Friendly Captcha",)
    assert finding.behaviors == ("captcha",)
    assert finding.evidence == (
        AntiBotEvidence(
            source="technology",
            indicator="friendly captcha",
            matched_value="Friendly Captcha",
            artifact="Friendly Captcha",
        ),
    )


def test_inspect_anti_bot_findings_canonicalizes_vendor_for_detected_technology() -> (
    None
):
    anti_bot_catalog = {
        "perimeterx": AntiBotTechnologyCatalogEntry(
            name="PerimeterX",
            vendor="HUMAN / PerimeterX",
            behaviors=("bot_management",),
        )
    }
    findings = inspect_anti_bot_findings(
        headers={},
        body=b"<html></html>",
        technologies=(
            Technology(
                raw_name="PerimeterX",
                name="PerimeterX",
                categories=("Security",),
                security_relevant=True,
            ),
        ),
        anti_bot_catalog=anti_bot_catalog,
        anti_bot_aliases=derive_anti_bot_alias_catalog(anti_bot_catalog),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "HUMAN"
    assert finding.products == ("PerimeterX",)
    assert finding.behaviors == ("bot_management",)
    assert finding.evidence == (
        AntiBotEvidence(
            source="technology",
            indicator="perimeterx",
            matched_value="PerimeterX",
            artifact="PerimeterX",
        ),
    )
