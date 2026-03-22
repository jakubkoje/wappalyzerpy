from __future__ import annotations

import json

from wappalyzer_pure import ArtifactCaptureOptions, analyze_response


def main() -> int:
    headers = {
        "Server": "cloudflare",
        "Set-Cookie": ["__cf_bm=opaque; Path=/; HttpOnly"],
        "Content-Type": "text/html; charset=utf-8",
    }
    body = """
    <html>
      <head>
        <script src="/static/app.js"></script>
      </head>
      <body>
        Access denied - Sucuri Website Firewall
      </body>
    </html>
    """

    result = analyze_response(
        headers,
        body,
        capture_artifacts=ArtifactCaptureOptions(
            body_excerpt_chars=96,
            captured_at_utc="2026-03-22T00:00:00Z",
        ),
    )

    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
