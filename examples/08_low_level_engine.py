from __future__ import annotations

from wappalyzer_pure import FingerprintDataSource, get_default_wappalyzer


def main() -> int:
    client = get_default_wappalyzer(FingerprintDataSource.MERGED)
    headers = {
        "Server": ["cloudflare"],
        "Content-Type": ["text/html; charset=utf-8"],
        "Set-Cookie": ["__cf_bm=opaque; Path=/; HttpOnly"],
    }
    body = b"""
    <html>
      <head>
        <title>Low-Level Engine Example</title>
      </head>
      <body></body>
    </html>
    """

    fingerprint_result = client.fingerprint(headers, body)
    fingerprint_with_title, title = client.fingerprint_with_title(headers, body)
    fingerprint_with_info = client.fingerprint_with_info(headers, body)

    print("fingerprint():")
    print(sorted(fingerprint_result))

    print("\nfingerprint_with_title():")
    print(f"title={title!r}")
    print(sorted(fingerprint_with_title))

    print("\nfingerprint_with_info():")
    for name, info in sorted(fingerprint_with_info.items()):
        print(f"- {name}: categories={info.categories} website={info.website!r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
