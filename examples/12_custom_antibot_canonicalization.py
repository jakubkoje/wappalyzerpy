from __future__ import annotations

import json

from wappalyzer_pure import Wappalyzer, analyze_response


def main() -> int:
    fingerprints_json = json.dumps(
        {
            "apps": {
                "PerimeterX": {
                    "cats": [16],
                    "headers": {"server": "perimeterx"},
                    "description": (
                        "PerimeterX is a bot management and challenge platform."
                    ),
                    "website": "https://www.humansecurity.com/",
                },
                "Akamai Bot Manager": {
                    "cats": [16],
                    "cookies": {"_abck": ""},
                    "description": (
                        "Akamai Bot Manager mitigates bots, scraping, and automated threats."
                    ),
                    "website": "https://www.akamai.com/",
                },
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
            "Server": "perimeterx",
            "Set-Cookie": ["_abck=opaque; Path=/; HttpOnly"],
        },
        "<html>px-captcha</html>",
        client=client,
    )

    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
