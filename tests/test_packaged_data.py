from __future__ import annotations

from wappalyzer_pure.engine import get_default_wappalyzer


def test_packaged_fingerprints_detect_cloudflare_from_header() -> None:
    client = get_default_wappalyzer()
    info = client.fingerprint_with_info({"Server": ["cloudflare"]}, b"")

    assert "Cloudflare" in info
    assert info["Cloudflare"].website == "https://www.cloudflare.com"
