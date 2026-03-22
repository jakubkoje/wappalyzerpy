from __future__ import annotations

import json

from wappalyzer_pure import analyze_response


def main() -> int:
    headers = {
        "Server": "cloudflare",
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": [
            "__cf_bm=opaque; Path=/; HttpOnly",
            "cf_clearance=challenge-passed; Path=/; Secure",
        ],
        "Content-Security-Policy": "default-src 'self'",
    }
    body = """
    <html>
      <head>
        <title>Offline Example</title>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
      </head>
      <body>
        Just a moment...
        /cdn-cgi/challenge-platform/
      </body>
    </html>
    """

    result = analyze_response(headers, body)

    print("Technologies:")
    for technology in result.technologies:
        print(f"- {technology.display_name} {technology.categories}")

    print("\nAnti-bot findings:")
    for finding in result.anti_bot_findings:
        print(f"- {finding.vendor} score={finding.score} behaviors={finding.behaviors}")

    print("\nFull JSON:")
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
