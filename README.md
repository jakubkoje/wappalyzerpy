# wappalyzer-pure

Pure-Python website technology detection from HTTP responses.

`wappalyzer-pure` fingerprints technologies from headers, cookies, raw HTML,
`<meta>` tags, `<script src>` URLs, inline JavaScript, and optionally a bounded
set of external JavaScript files. It is library-first, with a small CLI for ad
hoc scans.

The package ships three packaged datasets:

- `merged` as the default source, built from both upstreams during sync
- `enthec` as a source-specific view
- `httparchive` as a source-specific view

## Features

- Pure Python, no Go bridge or native build step
- Analyze an already-fetched response with `analyze_response(...)`
- Fetch and fingerprint a URL directly with `analyze_url(...)`
- Detect technologies from headers, cookies, HTML, meta tags, script URLs, and
  inline script contents
- Optionally fetch same-origin external JavaScript with explicit limits
- Return structured result objects instead of raw strings
- Use the merged default dataset or inspect the individual upstream datasets
- Expose a lower-level `Wappalyzer` engine for custom datasets
- Report common security headers separately

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
print(result.final_url)
print([tech.display_name for tech in result.technologies])
print([tech.name for tech in result.security_technologies])
```

### Choose a packaged fingerprint source

`merged` is the default packaged dataset. To inspect one upstream directly, pass
a source explicitly.

```python
from wappalyzer_pure import FingerprintDataSource, analyze_url

result = analyze_url(
    'https://example.com',
    source=FingerprintDataSource.HTTPARCHIVE,
)
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
    <script>window.inlinecms = "3.7";</script>
  </head>
</html>
"""

result = analyze_response(headers, body)

for technology in result.technologies:
    print(technology.display_name, technology.categories)
```

### Enable bounded external script fetching

Inline `<script>` contents are matched automatically. External script fetching is
opt-in.

```python
from wappalyzer_pure import (
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    analyze_url,
)

result = analyze_url(
    'https://example.com',
    script_analysis=ScriptAnalysisOptions(
        fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        max_external_scripts=8,
        max_bytes_per_script=256_000,
        max_total_script_bytes=1_048_576,
    ),
)

print([tech.display_name for tech in result.technologies])
```

If you already fetched the page yourself, use `analyze_response(...)` with
`response_url=...` so relative `<script src>` values can be resolved correctly.

```python
from wappalyzer_pure import (
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    analyze_response,
)

result = analyze_response(
    headers,
    body,
    response_url='https://example.com/app',
    script_analysis=ScriptAnalysisOptions(
        fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
    ),
)
```

## Public API

The package exports:

- `analyze_url`
- `analyze_response`
- `FingerprintDataSource`
- `ScriptAnalysisOptions`
- `ScriptFetchPolicy`
- `AnalysisResult`
- `Technology`
- `SecurityHeaderStatus`
- `Wappalyzer`
- `get_default_wappalyzer`

### `analyze_url`

```python
def analyze_url(
    url: str,
    *,
    timeout: float = 10.0,
    request_headers: Mapping[str, str] | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    opener: urllib_request.OpenerDirector | None = None,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    script_analysis: ScriptAnalysisOptions | None = None,
    client: Wappalyzer | None = None,
) -> AnalysisResult: ...
```

Fetches a URL with `urllib`, fingerprints the response, and returns an
`AnalysisResult`.

Parameters:

- `url`: target URL to fetch
- `timeout`: request timeout in seconds for the main response and optional script fetches
- `request_headers`: additional request headers for the initial page request
- `user_agent`: user agent string for the initial page request
- `opener`: custom `urllib` opener to use instead of `urllib.request.build_opener()`
- `source`: packaged fingerprint source to use when `client` is not provided
- `script_analysis`: optional external script fetch settings
- `client`: custom `Wappalyzer` instance; overrides packaged source loading

Returns:

- `AnalysisResult` with `target_url`, `final_url`, `status_code`, `technologies`,
  `security_headers`, and `body_length`

Behavior notes:

- HTTP error responses are still fingerprinted when a response body is available
- `Referer` is forwarded to optional external script requests
- `client` takes precedence over `source`

### `analyze_response`

```python
def analyze_response(
    headers: Mapping[str, str | bytes | Sequence[str | bytes]],
    body: bytes | bytearray | memoryview | str,
    *,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    response_url: str | None = None,
    script_analysis: ScriptAnalysisOptions | None = None,
    script_timeout: float = 10.0,
    script_request_headers: Mapping[str, str] | None = None,
    script_opener: urllib_request.OpenerDirector | None = None,
    client: Wappalyzer | None = None,
) -> AnalysisResult: ...
```

Fingerprints an already-fetched response and returns an `AnalysisResult`.

Accepted inputs:

- `headers`: `Mapping[str, str | bytes | Sequence[str | bytes]]`
- `body`: `str | bytes | bytearray | memoryview`

Parameters:

- `source`: packaged fingerprint source to use when `client` is not provided
- `response_url`: original response URL; required when external script fetching is enabled
- `script_analysis`: optional external script fetch settings
- `script_timeout`: timeout in seconds for optional external script requests
- `script_request_headers`: headers to send with optional external script requests
- `script_opener`: custom `urllib` opener for optional external script requests
- `client`: custom `Wappalyzer` instance; overrides packaged source loading

Returns:

- `AnalysisResult` with detected technologies and tracked security headers

Raises:

- `ValueError` when external script fetching is enabled but `response_url` is missing

### Example JSON Output

This is real output from:

```python
from wappalyzer_pure import analyze_response

headers = {
    'Server': 'cloudflare',
    'Content-Type': 'text/html; charset=utf-8',
    'Set-Cookie': ['__cf_bm=example'],
    'Content-Security-Policy': "default-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
}
body = '<html><head><title>Example</title></head><body></body></html>'

result = analyze_response(headers, body)
print(result.to_dict())
```

```json
{
  "target_url": null,
  "final_url": null,
  "status_code": null,
  "body_length": 61,
  "technologies": [
    {
      "raw_name": "Cloudflare",
      "name": "Cloudflare",
      "version": null,
      "display_name": "Cloudflare",
      "description": "Cloudflare is a web-infrastructure and website-security company, providing content-delivery-network services, DDoS mitigation, Internet security, and distributed domain-name-server services.",
      "website": "https://www.cloudflare.com",
      "cpe": "cpe:2.3:a:cloudflare:cloudflare:*:*:*:*:*:*:*:*",
      "icon": "CloudFlare.svg",
      "categories": [
        "CDN"
      ],
      "security_relevant": true
    },
    {
      "raw_name": "HSTS",
      "name": "HSTS",
      "version": null,
      "display_name": "HSTS",
      "description": "HTTP Strict Transport Security (HSTS) informs browsers that the site should only be accessed using HTTPS.",
      "website": "https://www.rfc-editor.org/rfc/rfc6797#section-6.1",
      "cpe": null,
      "icon": null,
      "categories": [
        "Security"
      ],
      "security_relevant": true
    },
    {
      "raw_name": "Cloudflare Bot Management",
      "name": "Cloudflare Bot Management",
      "version": null,
      "display_name": "Cloudflare Bot Management",
      "description": "Cloudflare bot management solution identifies and mitigates automated traffic to protect websites from bad bots.",
      "website": "https://www.cloudflare.com/en-gb/products/bot-management/",
      "cpe": null,
      "icon": "CloudFlare.svg",
      "categories": [
        "Security"
      ],
      "security_relevant": true
    }
  ],
  "security_headers": [
    {
      "name": "Content-Security-Policy",
      "present": true,
      "value": "default-src 'self'"
    },
    {
      "name": "Strict-Transport-Security",
      "present": true,
      "value": "max-age=31536000; includeSubDomains"
    },
    {
      "name": "X-Frame-Options",
      "present": false,
      "value": null
    },
    {
      "name": "X-Content-Type-Options",
      "present": false,
      "value": null
    },
    {
      "name": "Referrer-Policy",
      "present": false,
      "value": null
    },
    {
      "name": "Permissions-Policy",
      "present": false,
      "value": null
    },
    {
      "name": "Cross-Origin-Opener-Policy",
      "present": false,
      "value": null
    },
    {
      "name": "Cross-Origin-Embedder-Policy",
      "present": false,
      "value": null
    },
    {
      "name": "Cross-Origin-Resource-Policy",
      "present": false,
      "value": null
    }
  ]
}
```

### `FingerprintDataSource`

Choose which packaged dataset to use when you are not passing a custom
`Wappalyzer` client.

Available values:

- `FingerprintDataSource.MERGED`
- `FingerprintDataSource.ENTHEC`
- `FingerprintDataSource.HTTPARCHIVE`

Default:

- `FingerprintDataSource.MERGED`

### `ScriptAnalysisOptions`

```python
@dataclass(frozen=True, slots=True)
class ScriptAnalysisOptions:
    fetch_policy: ScriptFetchPolicy = ScriptFetchPolicy.OFF
    max_external_scripts: int = 8
    max_bytes_per_script: int = 256_000
    max_total_script_bytes: int = 1_048_576
```

Controls the optional external JavaScript fetch step.

Fields:

- `fetch_policy`: whether external script fetching is disabled or limited to same-origin
- `max_external_scripts`: maximum number of explicit `<script src>` URLs to fetch
- `max_bytes_per_script`: hard byte limit per fetched script
- `max_total_script_bytes`: combined byte limit across all fetched scripts

### `ScriptFetchPolicy`

Available values:

- `ScriptFetchPolicy.OFF`
- `ScriptFetchPolicy.SAME_ORIGIN`

### `get_default_wappalyzer`

```python
def get_default_wappalyzer(
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
) -> Wappalyzer: ...
```

Returns the lazily loaded packaged engine for the selected source.

### `Wappalyzer`

Low-level engine API for custom datasets or lower-level matching.

Constructors:

```python
from wappalyzer_pure import FingerprintDataSource, Wappalyzer

client = Wappalyzer.from_package_data()
client = Wappalyzer.from_package_data(source=FingerprintDataSource.MERGED)
client = Wappalyzer.from_package_data(source=FingerprintDataSource.HTTPARCHIVE)
client = Wappalyzer.from_json_strings(fingerprints_json, categories_json)
```

Common methods:

```python
client.fingerprint(
    headers,
    body,
    *,
    html_artifacts=None,
    extra_script_contents=(),
) -> dict[str, None]

client.fingerprint_with_title(
    headers,
    body,
    *,
    html_artifacts=None,
    extra_script_contents=(),
) -> tuple[dict[str, None], str]

client.fingerprint_with_info(
    headers,
    body,
    *,
    html_artifacts=None,
    extra_script_contents=(),
) -> dict[str, AppInfo]
```

## Result Objects

### `AnalysisResult`

```python
@dataclass(frozen=True, slots=True)
class AnalysisResult:
    target_url: str | None = None
    final_url: str | None = None
    status_code: int | None = None
    technologies: tuple[Technology, ...] = ()
    security_headers: tuple[SecurityHeaderStatus, ...] = ()
    body_length: int = 0
```

Returned by `analyze_url(...)` and `analyze_response(...)`.

Fields:

- `target_url`: original URL passed to `analyze_url`; `None` for `analyze_response`
- `final_url`: final response URL after redirects; `None` for `analyze_response`
- `status_code`: HTTP status code for `analyze_url`; `None` for `analyze_response`
- `technologies`: detected technologies as `tuple[Technology, ...]`
- `security_headers`: tracked header statuses as `tuple[SecurityHeaderStatus, ...]`
- `body_length`: response body length in bytes after coercion

Helpers:

- `security_technologies`: filtered `technologies` tuple containing only security-relevant entries
- `to_dict(security_only: bool = False)`: JSON-ready dictionary representation

### `Technology`

```python
@dataclass(frozen=True, slots=True)
class Technology:
    raw_name: str
    name: str
    version: str | None = None
    description: str | None = None
    website: str | None = None
    cpe: str | None = None
    icon: str | None = None
    categories: tuple[str, ...] = ()
    security_relevant: bool = False
```

Represents one detected technology.

Helpers:

- `display_name`: `name` or `name:version` when a version is available
- `to_dict()`: JSON-ready dictionary representation

### `SecurityHeaderStatus`

```python
@dataclass(frozen=True, slots=True)
class SecurityHeaderStatus:
    name: str
    present: bool
    value: str | None = None
```

Represents one tracked security header.

Helpers:

- `to_dict()`: JSON-ready dictionary representation

## CLI

```bash
uv run wappalyzer-pure scan https://example.com
uv run wappalyzer-pure scan https://example.com --json
uv run wappalyzer-pure scan https://example.com --json --security-only
uv run wappalyzer-pure scan https://example.com --fetch-scripts same-origin
uv run wappalyzer-pure scan https://example.com --source httparchive
```

Script-related flags:

- `--source {merged,enthec,httparchive}`
- `--fetch-scripts {off,same-origin}`
- `--max-external-scripts`
- `--max-bytes-per-script`
- `--max-total-script-bytes`

## Security Headers

The packaged security-header dataset currently tracks:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Resource-Policy`

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

categories_json = json.dumps({'31': {'name': 'CDN', 'priority': 1}})

client = Wappalyzer.from_json_strings(fingerprints_json, categories_json)
result = analyze_response({'Server': 'cloudflare'}, b'', client=client)
print(result.to_dict())
```

## Limitations

This package intentionally stays response-based.

It does not:

- execute JavaScript
- evaluate browser DOM rules
- emulate a real browser runtime
- crawl arbitrary script graphs

External script fetching is limited to explicit `<script src>` references and is
only enabled when you opt into it.

## Development

Run tests:

```bash
uv run pytest
```

Run formatting, linting, and type checking:

```bash
uv run ruff check src tests main.py
uv run ruff format --check src tests main.py
uv run ty check src tests main.py
```

Refresh the packaged fingerprint data manually:

```bash
uv run python -m wappalyzer_pure.sync_data
```

That command refreshes both upstream datasets, compares them, and rebuilds the
default merged dataset in one pass.

Refresh only one packaged upstream and write it to explicit output files:

```bash
uv run python -m wappalyzer_pure.sync_data --source enthec
uv run python -m wappalyzer_pure.sync_data --source httparchive
```

## Upstream

This package is a pure-Python implementation inspired by
`projectdiscovery/wappalyzergo` and uses vendored fingerprint data derived from
`enthec/webappanalyzer` and `HTTPArchive/wappalyzer`.
