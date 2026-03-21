from __future__ import annotations

from wappalyzer_pure.sync_data import _normalize_categories, _normalize_fingerprint


def test_normalize_fingerprint_matches_packaged_shape() -> None:
    payload = {
        "cats": [31, 1],
        "css": [".Example", ".alpha"],
        "dom": ["#app", ".hero"],
        "cookies": {"SessionID": "ABC", "empty": ""},
        "js": {"AppConfig": "window.AppConfig"},
        "headers": {"Server": "CloudFlare"},
        "html": "META GENERATOR",
        "scripts": ["One\\.JS", "two\\.js"],
        "scriptSrc": "CDN\\.EXAMPLE\\.COM/",
        "meta": {
            "Generator": "WordPress ([0-9.]+)\\;version:\\1",
            "Author": ["Example", "Another"],
            "Empty": "",
        },
        "implies": "PHP",
        "description": "Reverse proxy and CDN",
        "website": "https://example.com",
        "cpe": "cpe:/a:example:product",
        "icon": "example.svg",
    }

    normalized = _normalize_fingerprint(payload)

    assert normalized["cats"] == [31, 1]
    assert normalized["css"] == [".Example", ".alpha"]
    assert normalized["dom"] == {
        "#app": {"exists": ""},
        ".hero": {"exists": ""},
    }
    assert normalized["cookies"] == {"empty": "", "sessionid": "abc"}
    assert normalized["js"] == {"AppConfig": "window.AppConfig"}
    assert normalized["headers"] == {"server": "cloudflare"}
    assert normalized["html"] == ["meta generator"]
    assert normalized["scripts"] == ["one\\.js", "two\\.js"]
    assert normalized["scriptSrc"] == ["cdn\\.example\\.com/"]
    assert normalized["meta"] == {
        "author": ["another", "example"],
        "empty": [],
        "generator": ["wordpress ([0-9.]+)\\;version:\\1"],
    }
    assert normalized["implies"] == ["PHP"]
    assert normalized["description"] == "Reverse proxy and CDN"
    assert normalized["website"] == "https://example.com"
    assert normalized["cpe"] == "cpe:/a:example:product"
    assert normalized["icon"] == "example.svg"


def test_normalize_categories_sorts_numeric_keys() -> None:
    categories = {
        "10": {"name": "Blogs", "priority": 1, "groups": [3]},
        "2": {"name": "Message boards", "priority": 1, "groups": [3, 4, 18]},
        "1": {"name": "CMS", "priority": 1, "groups": [3]},
    }

    normalized = _normalize_categories(categories)

    assert list(normalized) == ["1", "2", "10"]
