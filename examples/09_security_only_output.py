from __future__ import annotations

import json

from wappalyzer_pure import analyze_response


def main() -> int:
    result = analyze_response(
        {
            "Server": "cloudflare",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Set-Cookie": ["__cf_bm=opaque"],
        },
        "<html></html>",
    )

    print("Full technology list:")
    print([technology.display_name for technology in result.technologies])

    print("\nsecurity_only JSON:")
    print(json.dumps(result.to_dict(security_only=True), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
