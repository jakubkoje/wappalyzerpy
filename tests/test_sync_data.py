from __future__ import annotations

from wappalyzer_pure.data_sources import FingerprintDataSource
from wappalyzer_pure.sync_data import (
    _build_comparison,
    _build_merged_dataset,
    _normalize_categories,
    _normalize_fingerprint,
    default_sync_paths,
)


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


def test_default_sync_paths_builds_source_specific_dataset_files() -> None:
    paths = default_sync_paths()

    assert paths.datasets[FingerprintDataSource.MERGED].fingerprints.name == (
        "fingerprints_merged_data.json"
    )
    assert paths.datasets[FingerprintDataSource.MERGED].categories.name == (
        "categories_merged_data.json"
    )
    assert paths.datasets[FingerprintDataSource.ENTHEC].fingerprints.name == (
        "fingerprints_enthec_data.json"
    )
    assert paths.datasets[FingerprintDataSource.ENTHEC].categories.name == (
        "categories_enthec_data.json"
    )
    assert paths.datasets[FingerprintDataSource.HTTPARCHIVE].fingerprints.name == (
        "fingerprints_httparchive_data.json"
    )
    assert paths.datasets[FingerprintDataSource.HTTPARCHIVE].categories.name == (
        "categories_httparchive_data.json"
    )


def test_build_comparison_reports_shared_and_source_only_counts() -> None:
    comparison = _build_comparison(
        {
            FingerprintDataSource.ENTHEC: (
                {
                    "SharedSame": {"cats": [1]},
                    "SharedDifferent": {"cats": [2]},
                    "OnlyEnthec": {"cats": [3]},
                },
                {
                    "1": {"name": "CMS", "priority": 1},
                    "2": {"name": "CDN", "priority": 1},
                },
            ),
            FingerprintDataSource.HTTPARCHIVE: (
                {
                    "SharedSame": {"cats": [1]},
                    "SharedDifferent": {"cats": [99]},
                    "OnlyHttpArchive": {"cats": [4]},
                },
                {
                    "1": {"name": "CMS", "priority": 1},
                    "3": {"name": "Analytics", "priority": 1},
                },
            ),
        }
    )

    assert comparison == {
        "technologies": {
            "shared": 2,
            "only_enthec": 1,
            "only_httparchive": 1,
            "identical_shared": 1,
            "different_shared": 1,
        },
        "categories": {
            "shared": 1,
            "only_enthec": 1,
            "only_httparchive": 1,
            "identical_shared": 1,
            "different_shared": 0,
        },
    }


def test_build_merged_dataset_unions_lists_and_prefers_primary_scalars() -> None:
    merged_apps, merged_categories = _build_merged_dataset(
        {
            FingerprintDataSource.ENTHEC: (
                {
                    "Shared": {
                        "cats": [1, 2],
                        "icon": "shared.svg",
                        "meta": {"generator": ["alpha"]},
                    },
                    "OnlyEnthec": {"website": "https://enthec.example"},
                },
                {
                    "1": {"name": "CMS", "priority": 1},
                },
            ),
            FingerprintDataSource.HTTPARCHIVE: (
                {
                    "Shared": {
                        "cats": [2, 3],
                        "icon": "shared.png",
                        "meta": {"generator": ["beta"]},
                    },
                    "OnlyHttpArchive": {"website": "https://http.example"},
                },
                {
                    "1": {
                        "name": "CMS",
                        "priority": 1,
                        "description": "Content management systems",
                    },
                },
            ),
        }
    )

    assert merged_apps == {
        "OnlyEnthec": {"website": "https://enthec.example"},
        "OnlyHttpArchive": {"website": "https://http.example"},
        "Shared": {
            "cats": [1, 2, 3],
            "icon": "shared.svg",
            "meta": {"generator": ["alpha", "beta"]},
        },
    }
    assert merged_categories == {
        "1": {
            "name": "CMS",
            "priority": 1,
            "description": "Content management systems",
        }
    }
