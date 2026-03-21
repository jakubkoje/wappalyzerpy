from __future__ import annotations

import json

from wappalyzer_pure import analyze_url

TARGET_URL = "https://upfan.io"
SECURITY_ONLY = True


def main() -> int:
    result = analyze_url(TARGET_URL)
    print(json.dumps(result.to_dict(security_only=SECURITY_ONLY), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
