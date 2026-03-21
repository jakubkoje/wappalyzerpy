from __future__ import annotations

import json

import pytest

from wappalyzer_pure.engine import Wappalyzer

FINGERPRINTS_JSON = json.dumps(
    {
        "apps": {
            "Apache HTTP Server": {
                "headers": {
                    "server": "(?:apache(?:$|/([\\d.]+)|[^/-])|(?:^|\\b)httpd)\\;version:\\1"
                },
                "cats": [22],
                "description": "Apache HTTP Server",
            },
            "CookieApp": {
                "cookies": {"sessionid": "^.+$"},
                "cats": [1],
            },
            "HTMLApp": {
                "html": ["powered by htmlapp"],
                "cats": [1],
            },
            "MetaCMS": {
                "meta": {"generator": ["metacms ([0-9.]+)\\;version:\\1"]},
                "cats": [1],
            },
            "ScriptApp": {
                "scriptSrc": ["/assets/script-([0-9.]+)\\.js\\;version:\\1"],
                "cats": [1],
            },
            "PrimaryApp": {
                "headers": {"x-powered-by": "primary"},
                "implies": ["ImpliedApp"],
                "cats": [1],
            },
            "ImpliedApp": {
                "cats": [1],
            },
        }
    }
)

CATEGORIES_JSON = json.dumps(
    {
        "1": {"name": "CMS", "priority": 1},
        "22": {"name": "Web servers", "priority": 1},
    }
)


@pytest.fixture
def client() -> Wappalyzer:
    return Wappalyzer.from_json_strings(FINGERPRINTS_JSON, CATEGORIES_JSON)


def test_fingerprint_matches_all_supported_parts(client: Wappalyzer) -> None:
    body = (
        b"<html><head><meta name='generator' content='MetaCMS 2.4'></head>"
        b"<body>powered by htmlapp<script src='/assets/script-9.1.js'></script></body></html>"
    )
    headers = {
        "Server": ["Apache/2.4.29"],
        "Set-Cookie": ["sessionid=abc123; Path=/"],
        "X-Powered-By": ["primary"],
    }
    matches = client.fingerprint(headers, body)

    expected = {
        "Apache HTTP Server:2.4.29",
        "CookieApp",
        "HTMLApp",
        "MetaCMS:2.4",
        "ScriptApp:9.1",
        "PrimaryApp",
        "ImpliedApp",
    }
    assert set(matches) == expected


def test_fingerprint_with_info_returns_categories(client: Wappalyzer) -> None:
    info = client.fingerprint_with_info({"Server": ["Apache/2.4.29"]}, b"")
    apache = info["Apache HTTP Server:2.4.29"]
    assert apache.categories == ("Web servers",)
    assert apache.description == "Apache HTTP Server"
