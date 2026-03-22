from __future__ import annotations

import json

from wappalyzer_pure import Wappalyzer, analyze_response


def main() -> int:
    fingerprints_json = json.dumps(
        {
            "apps": {
                "ExampleShield": {
                    "cats": [16],
                    "headers": {"server": "exampleshield"},
                    "cookies": {"example_shield": ""},
                    "description": (
                        "ExampleShield is an anti-bot and CAPTCHA protection layer."
                    ),
                    "website": "https://example.invalid/exampleshield",
                }
            }
        }
    )
    categories_json = json.dumps(
        {
            "16": {
                "name": "Security",
                "priority": 1,
            }
        }
    )

    client = Wappalyzer.from_json_strings(fingerprints_json, categories_json)
    result = analyze_response(
        {
            "Server": "exampleshield",
            "Set-Cookie": ["example_shield=active; Path=/; HttpOnly"],
        },
        "<html></html>",
        client=client,
    )

    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
