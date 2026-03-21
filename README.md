# wappalyzerpy

Pure-Python website technology detection from HTTP responses.

`wappalyzerpy` fingerprints technologies from headers, cookies, HTML,
`<meta>` tags, and `<script src>` URLs. It is library-first, with a small CLI
for ad hoc scans.

## Features

- Pure Python, no Go bridge or native build step
- Detects technologies from response data you already have
- Can fetch a URL directly with `analyze_url(...)`
- Returns structured result objects instead of plain strings
- Exposes a lower-level `Wappalyzer` engine for custom datasets
- Tracks common security headers separately

## Install

For local development in this repository:

```bash
uv sync
```

## Quickstart

### Scan a URL

```python
from wappalyzer_pure import analyze_url

result = analyze_url('https://example.com')

print(result.status_code)
print([tech.display_name for tech in result.technologies])
print([tech.name for tech in result.security_technologies])
```

### Fingerprint an existing response

```python
from wappalyzer_pure import analyze_response

headers = {
    'Server': 'cloudflare',
    'Content-Type': 'text/html; charset=utf-8',
    'Set-Cookie': ['__cf_bm=example'],
}
body = """
<html>
  <head>
    <meta name="generator" content="ExampleCMS 1.2">
  </head>
</html>
"""

result = analyze_response(headers, body)

for technology in result.technologies:
    print(technology.display_name, technology.categories)
```

### Serialize to JSON-friendly output

```python
import json

from wappalyzer_pure import analyze_url

result = analyze_url('https://example.com')
print(json.dumps(result.to_dict(), indent=2))
```

## API

### `analyze_url(...) -> AnalysisResult`

Fetches a URL with `urllib`, fingerprints the response, and returns a structured
result.

Useful parameters:

- `timeout`
- `request_headers`
- `user_agent`
- `opener`
- `client`

### `analyze_response(...) -> AnalysisResult`

Fingerprints an already-fetched response.

Accepted inputs:

- headers as `dict[str, str]`, `dict[str, bytes]`, or multi-value sequences
- body as `str`, `bytes`, `bytearray`, or `memoryview`

Use this if your project already uses `requests`, `httpx`, `aiohttp`, or
another HTTP client and you only want the detection layer.

### `get_default_wappalyzer() -> Wappalyzer`

Returns the lazily loaded default engine backed by the packaged fingerprint
data.

### `Wappalyzer`

Lower-level engine API for direct control or custom datasets.

Constructors:

```python
from wappalyzer_pure import Wappalyzer

client = Wappalyzer.from_package_data()
client = Wappalyzer.from_json_strings(fingerprints_json, categories_json)
```

Common methods:

- `fingerprint(headers, body) -> dict[str, None]`
- `fingerprint_with_title(headers, body) -> tuple[dict[str, None], str]`
- `fingerprint_with_info(headers, body) -> dict[str, AppInfo]`

## Result Objects

### `AnalysisResult`

Returned by both `analyze_url(...)` and `analyze_response(...)`.

Fields:

- `target_url`
- `final_url`
- `status_code`
- `technologies`
- `security_headers`
- `body_length`

Helpers:

- `security_technologies`
- `to_dict(security_only: bool = False)`

### `Technology`

Represents one detected technology.

Fields:

- `raw_name`
- `name`
- `version`
- `description`
- `website`
- `cpe`
- `icon`
- `categories`
- `security_relevant`

Helpers:

- `display_name`
- `to_dict()`

### `SecurityHeaderStatus`

Represents one tracked security header.

Fields:

- `name`
- `present`
- `value`

## Security Headers

The package reports these bundled security headers separately:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Resource-Policy`

## CLI

```bash
uv run wappalyzerpy scan https://example.com
uv run wappalyzerpy scan https://example.com --json
uv run wappalyzerpy scan https://example.com --json --security-only
```

## Custom Data

You can load your own fingerprint dataset:

```python
import json

from wappalyzer_pure import Wappalyzer, analyze_response

fingerprints_json = json.dumps(
    {
        'apps': {
            'Cloudflare': {
                'headers': {'server': 'cloudflare'},
                'cats': [31],
                'description': 'Reverse proxy and CDN',
            }
        }
    }
)

categories_json = json.dumps(
    {
        '31': {'name': 'CDN', 'priority': 1}
    }
)

client = Wappalyzer.from_json_strings(fingerprints_json, categories_json)
result = analyze_response({'Server': 'cloudflare'}, b'', client=client)
print(result.to_dict())
```

## Limitations

This package intentionally focuses on response-based detection.

It does not:

- execute JavaScript
- evaluate browser DOM rules
- emulate a real browser runtime

## Development

Run tests:

```bash
uv run pytest
```

Run type checking:

```bash
uv run ruff check src tests main.py
uv run ty check src tests main.py
```

Refresh the packaged fingerprint data manually:

```bash
uv run python -m wappalyzer_pure.sync_data
```

## Upstream

This package is a Python rewrite of the behavior used from
[`projectdiscovery/wappalyzergo`](https://github.com/projectdiscovery/wappalyzergo)
and uses vendored Wappalyzer-compatible fingerprint data from
[`enthec/webappanalyzer`](https://github.com/enthec/webappanalyzer).
