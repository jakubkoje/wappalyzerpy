from __future__ import annotations

from wappalyzer_pure.data_sources import FingerprintDataSource
from wappalyzer_pure.engine import get_default_wappalyzer


def test_packaged_fingerprints_detect_cloudflare_from_header_for_both_sources() -> None:
    for source in FingerprintDataSource:
        client = get_default_wappalyzer(source)
        info = client.fingerprint_with_info({"Server": ["cloudflare"]}, b"")

        assert "Cloudflare" in info
        assert info["Cloudflare"].website == "https://www.cloudflare.com"
        assert "cloudflare bot management" in client.anti_bot_catalog
        assert client.anti_bot_aliases.canonical_vendor_name("Akamai Bot Manager") == (
            "Akamai"
        )
