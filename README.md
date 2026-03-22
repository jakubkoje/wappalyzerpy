# wappalyzer-pure

Pure-Python website technology detection from HTTP responses.

`wappalyzer-pure` fingerprints technologies from headers, cookies, raw HTML,
`<meta>` tags, `<script src>` URLs, inline JavaScript, and optionally a bounded
set of external JavaScript files. It is library-first, with a small CLI for ad
hoc scans.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Quickstart](#quickstart)
- [Anti-Bot Findings](#anti-bot-findings)
- [Multi-Request Probing](#multi-request-probing)
- [Public API](#public-api)
- [Result Objects](#result-objects)
- [CLI](#cli)
- [Packaged Data](#packaged-data)
- [Security Headers](#security-headers)
- [Custom Data](#custom-data)
- [Limitations](#limitations)
- [Development](#development)
- [Upstream](#upstream)

The package ships three packaged fingerprint sources:

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
- Return structured anti-bot findings with exact matched artifacts
- Run optional multi-request probes for active detection checks
- Use the merged default source or inspect the individual upstream sources
- Expose a lower-level `Wappalyzer` engine for custom fingerprint data
- Report common security headers separately

## Install

For local development in this repository:

```bash
uv sync
```

## Quickstart

For a broader set of runnable usage patterns, see [examples/README.md](/Users/jakub/Projects/Projects/FIIT/DP/wappalyzer-pure/examples/README.md).

### Scan a URL

```python
from wappalyzer_pure import analyze_url

result = analyze_url('https://example.com')

print(result.status_code)
print(result.final_url)
print([tech.display_name for tech in result.technologies])
print([tech.name for tech in result.security_technologies])
print([finding.vendor for finding in result.anti_bot_findings])
```

### Choose a packaged fingerprint source

`merged` is the default packaged source. To inspect one upstream directly, pass
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

### Run active detection probes

```python
from wappalyzer_pure import ProbeOptions, probe_url

result = probe_url(
    'https://example.com',
    probe_options=ProbeOptions(
        repeat_request=True,
        follow_up_with_cookies=True,
        browser_like_request=True,
    ),
)

print(result.vendors)
print(result.challenge_observed)
for observation in result.observations:
    print(observation.name, observation.result.status_code)
```

### Capture lightweight response artifacts

```python
from wappalyzer_pure import ArtifactCaptureOptions, analyze_url

result = analyze_url(
    'https://example.com',
    capture_artifacts=ArtifactCaptureOptions(body_excerpt_chars=128),
)

print(result.artifacts.body_sha256 if result.artifacts else None)
print(result.artifacts.script_sources if result.artifacts else ())
```

## Anti-Bot Findings

`wappalyzer-pure` exposes a separate anti-bot layer through
`AnalysisResult.anti_bot_findings`.

This layer is part of the detection base. It gives you explicit
scraping-protection findings instead of forcing you to infer them from generic
technology names.

Current behavior:

- conservative by default, so generic CDN presence alone does not become an anti-bot finding
- combines curated response-signal rules with a generated anti-bot technology catalog built from the synced fingerprint sources
- normalizes anti-bot vendors and products to canonical labels before returning `AntiBotFinding`
- evidence-driven, with exact matched artifacts recorded from cookies, headers, body markers, script URLs, fetched script contents, and matched technologies
- derives `score` and `confidence` from configurable heuristic weights and thresholds stored in JSON rule data
- `analyze_url(...)` augments findings with suspicious status-code and redirect evidence when applicable
- optional active follow-up checks are available separately through `probe_url(...)`

Canonicalization behavior:

- `Akamai Bot Manager` findings normalize to vendor `Akamai`
- `HUMAN / PerimeterX` findings normalize to vendor `HUMAN`
- raw matched values stay available in `AntiBotEvidence`, so downstream code can still inspect the original technology or response artifact names

Data sources behind this layer:

- synced product fingerprints live under `src/wappalyzer_pure/data/fingerprints/`
- synced categories live under `src/wappalyzer_pure/data/categories/`
- generated anti-bot product catalog lives in `src/wappalyzer_pure/data/antibot/anti_bot_technologies_data.json`
- generated anti-bot alias map lives in `src/wappalyzer_pure/data/antibot/anti_bot_aliases_data.json`
- anti-bot catalog derivation rules live in `src/wappalyzer_pure/data/antibot/anti_bot_catalog_rules.json`
- anti-bot alias rules live in `src/wappalyzer_pure/data/antibot/anti_bot_alias_rules.json`
- curated response-signal rules live in `src/wappalyzer_pure/data/antibot/anti_bot_signals_data.json`

Current curated vendors:

- `Cloudflare`
- `Akamai`
- `Imperva`
- `DataDome`
- `HUMAN`
- `Kasada`
- `Sucuri`

Example:

```python
from wappalyzer_pure import analyze_response

result = analyze_response(
    {
        'Server': 'cloudflare',
        'CF-Ray': 'abc123',
        'Set-Cookie': ['__cf_bm=opaque; Path=/; HttpOnly'],
    },
    '<html></html>',
)

for finding in result.anti_bot_findings:
    print(finding.vendor, finding.confidence, finding.behaviors)
    for evidence in finding.evidence:
        print(
            evidence.source,
            evidence.indicator,
            evidence.matched_value,
            evidence.artifact,
        )
```

## Multi-Request Probing

`probe_url(...)` adds an optional active detection layer on top of the passive
response analysis.

Current probe observations:

- `initial`
- `repeat`
- `cookie_follow_up`
- `browser_like`

Probe summary fields:

- `vendors`
- `challenge_observed`
- `throttled`
- `observations`

This layer is still lightweight:

- it uses repeated HTTP requests, not a browser runtime
- it replays cookies explicitly from the first response
- it uses a browser-like header profile as an extra comparison point
- it does not yet execute JavaScript or collect rendered DOM state

## Public API

The package exports:

- `analyze_url`
- `analyze_response`
- `probe_url`
- `ArtifactCaptureOptions`
- `FingerprintDataSource`
- `ProbeOptions`
- `ProbeObservation`
- `ProbeResult`
- `ScriptAnalysisOptions`
- `ScriptFetchPolicy`
- `AnalysisResult`
- `AntiBotFinding`
- `AntiBotEvidence`
- `CapturedHeader`
- `ResponseArtifacts`
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
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
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
- `capture_artifacts`: `True` or `ArtifactCaptureOptions(...)` to attach lightweight response artifacts

Returns:

- `AnalysisResult` with `target_url`, `final_url`, `status_code`, `technologies`,
  `security_headers`, `body_length`, and optional `artifacts`

Behavior notes:

- HTTP error responses are still fingerprinted when a response body is available
- `Referer` is forwarded to optional external script requests
- `client` takes precedence over `source`
- anti-bot findings are enriched with suspicious status-code and redirect evidence

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
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
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
- `capture_artifacts`: `True` or `ArtifactCaptureOptions(...)` to attach lightweight response artifacts

Returns:

- `AnalysisResult` with detected technologies and tracked security headers

Raises:

- `ValueError` when external script fetching is enabled but `response_url` is missing

### `probe_url`

```python
def probe_url(
    url: str,
    *,
    timeout: float = 10.0,
    request_headers: Mapping[str, str] | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    opener: urllib_request.OpenerDirector | None = None,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    script_analysis: ScriptAnalysisOptions | None = None,
    client: Wappalyzer | None = None,
    probe_options: ProbeOptions | None = None,
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
) -> ProbeResult: ...
```

Runs multiple HTTP request profiles against the same target and returns a
`ProbeResult`.

Parameters:

- `url`: target URL to probe
- `timeout`: timeout in seconds for every probe request
- `request_headers`: additional headers for the base request profile
- `user_agent`: user agent for the base request profile
- `opener`: custom `urllib` opener
- `source`: packaged fingerprint source when `client` is not provided
- `script_analysis`: optional external script fetch settings applied to every observation
- `client`: custom `Wappalyzer` instance
- `probe_options`: controls which follow-up probes are executed
- `capture_artifacts`: `True` or `ArtifactCaptureOptions(...)` to attach artifacts to every observation result

Returns:

- `ProbeResult` with one `ProbeObservation` per executed request profile

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
  "anti_bot_findings": [
    {
      "vendor": "Cloudflare",
      "score": 7,
      "confidence": "high",
      "products": [
        "Cloudflare Bot Management"
      ],
      "behaviors": [
        "bot_management"
      ],
      "evidence": [
        {
          "source": "cookie",
          "indicator": "__cf_bm",
          "matched_value": "__cf_bm",
          "artifact": "__cf_bm=example"
        },
        {
          "source": "header_value",
          "indicator": "server",
          "matched_value": "cloudflare",
          "artifact": "server: cloudflare"
        },
        {
          "source": "technology",
          "indicator": "cloudflare bot management",
          "matched_value": "Cloudflare Bot Management",
          "artifact": "Cloudflare Bot Management"
        }
      ]
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
  ],
  "artifacts": null
}
```

### `FingerprintDataSource`

Choose which packaged source to use when you are not passing a custom
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

### `ArtifactCaptureOptions`

```python
@dataclass(frozen=True, slots=True)
class ArtifactCaptureOptions:
    body_excerpt_chars: int = 256
    captured_at_utc: str | None = None
```

Controls the optional artifact capture attached to `AnalysisResult`.

Fields:

- `body_excerpt_chars`: maximum number of decoded response-body characters to retain
- `captured_at_utc`: optional explicit UTC timestamp to store instead of generating one during URL fetches

### `ProbeOptions`

```python
@dataclass(frozen=True, slots=True)
class ProbeOptions:
    repeat_request: bool = True
    follow_up_with_cookies: bool = True
    browser_like_request: bool = True
    browser_user_agent: str = DEFAULT_BROWSER_USER_AGENT
```

Controls which active probe requests are sent by `probe_url(...)`.

### `get_default_wappalyzer`

```python
def get_default_wappalyzer(
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
) -> Wappalyzer: ...
```

Returns the lazily loaded packaged engine for the selected source.

### `Wappalyzer`

Low-level engine API for custom fingerprint data or lower-level matching.

Constructors:

```python
from wappalyzer_pure import FingerprintDataSource, Wappalyzer

client = Wappalyzer.from_package_data()
client = Wappalyzer.from_package_data(source=FingerprintDataSource.MERGED)
client = Wappalyzer.from_package_data(source=FingerprintDataSource.HTTPARCHIVE)
client = Wappalyzer.from_json_strings(fingerprints_json, categories_json)
```

`Wappalyzer.from_json_strings(...)` also derives an anti-bot technology catalog
from the supplied fingerprint and category payloads, so custom datasets still
participate in anti-bot product detection without using the packaged sync data.

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
    anti_bot_findings: tuple[AntiBotFinding, ...] = ()
    security_headers: tuple[SecurityHeaderStatus, ...] = ()
    body_length: int = 0
    artifacts: ResponseArtifacts | None = None
```

Returned by `analyze_url(...)` and `analyze_response(...)`.

Fields:

- `target_url`: original URL passed to `analyze_url`; `None` for `analyze_response`
- `final_url`: final response URL after redirects; `None` for `analyze_response`
- `status_code`: HTTP status code for `analyze_url`; `None` for `analyze_response`
- `technologies`: detected technologies as `tuple[Technology, ...]`
- `anti_bot_findings`: scraping-protection findings as `tuple[AntiBotFinding, ...]`
- `security_headers`: tracked header statuses as `tuple[SecurityHeaderStatus, ...]`
- `body_length`: response body length in bytes after coercion
- `artifacts`: optional lightweight captured artifacts as `ResponseArtifacts | None`

Helpers:

- `security_technologies`: filtered `technologies` tuple containing only security-relevant entries
- `to_dict(security_only: bool = False)`: JSON-ready dictionary representation

### `AntiBotFinding`

```python
@dataclass(frozen=True, slots=True)
class AntiBotFinding:
    vendor: str
    score: int
    confidence: str
    products: tuple[str, ...] = ()
    behaviors: tuple[str, ...] = ()
    evidence: tuple[AntiBotEvidence, ...] = ()
```

Represents one anti-bot or scraping-protection finding derived from the passive
response analysis.

`vendor` and `products` are canonicalized labels. Original matched names remain
visible through `evidence`.

`score` and `confidence` are heuristic outputs derived from configured rule
weights and thresholds. They are explicit and reproducible, but they are not an
empirically calibrated research metric by themselves.

Helpers:

- `to_dict()`: JSON-ready dictionary representation

### `AntiBotEvidence`

```python
@dataclass(frozen=True, slots=True)
class AntiBotEvidence:
    source: str
    indicator: str
    matched_value: str | None = None
    artifact: str | None = None
```

Represents one matched anti-bot signal.

Fields:

- `source`: signal origin such as `cookie`, `header_value`, `body`, `script_source`, `script_content`, `status_code`, or `redirect`
- `indicator`: normalized rule indicator that matched
- `matched_value`: exact matched value
- `artifact`: exact matched artifact or snippet used as evidence

Helpers:

- `to_dict()`: JSON-ready dictionary representation

### `CapturedHeader`

```python
@dataclass(frozen=True, slots=True)
class CapturedHeader:
    name: str
    values: tuple[str, ...]
```

Represents one normalized response header entry inside `ResponseArtifacts`.

### `ResponseArtifacts`

```python
@dataclass(frozen=True, slots=True)
class ResponseArtifacts:
    captured_at_utc: str | None = None
    headers: tuple[CapturedHeader, ...] = ()
    set_cookie_values: tuple[str, ...] = ()
    script_sources: tuple[str, ...] = ()
    fetched_script_urls: tuple[str, ...] = ()
    body_sha256: str | None = None
    body_excerpt: str | None = None
```

Optional lightweight response artifacts attached to `AnalysisResult`.

Fields:

- `captured_at_utc`: explicit or generated UTC timestamp when artifacts were captured
- `headers`: normalized response headers as `tuple[CapturedHeader, ...]`
- `set_cookie_values`: raw `Set-Cookie` header values
- `script_sources`: discovered `<script src>` values from the response body
- `fetched_script_urls`: external script URLs actually fetched during optional script analysis
- `body_sha256`: SHA-256 hash of the response body
- `body_excerpt`: leading decoded body excerpt, capped by `ArtifactCaptureOptions.body_excerpt_chars`

### `ProbeObservation`

```python
@dataclass(frozen=True, slots=True)
class ProbeObservation:
    name: str
    result: AnalysisResult
    request_headers: tuple[tuple[str, str], ...] = ()
    request_cookie_names: tuple[str, ...] = ()
    response_cookie_names: tuple[str, ...] = ()
```

Represents one active probe request.

Helpers:

- `redirected`
- `challenge_observed`
- `throttled`
- `to_dict()`

### `ProbeResult`

```python
@dataclass(frozen=True, slots=True)
class ProbeResult:
    observations: tuple[ProbeObservation, ...] = ()
```

Represents the full multi-request probe run.

Helpers:

- `challenge_observed`
- `throttled`
- `vendors`
- `to_dict()`

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
uv run wappalyzer-pure scan https://example.com --json --artifacts
uv run wappalyzer-pure scan https://example.com --source httparchive
uv run wappalyzer-pure probe https://example.com --json
uv run wappalyzer-pure probe https://example.com --json --artifacts
uv run wappalyzer-pure probe https://example.com --no-browser-like
```

Script-related flags:

- `--source {merged,enthec,httparchive}`
- `--fetch-scripts {off,same-origin}`
- `--max-external-scripts`
- `--max-bytes-per-script`
- `--max-total-script-bytes`
- `--artifacts`
- `--body-excerpt-chars`

Probe-related flags:

- `--no-repeat`
- `--no-cookie-follow-up`
- `--no-browser-like`

## Packaged Data

The package data is split by responsibility:

- `src/wappalyzer_pure/data/fingerprints/`: synced Wappalyzer-style technology fingerprints
- `src/wappalyzer_pure/data/categories/`: synced category metadata
- `src/wappalyzer_pure/data/antibot/anti_bot_technologies_data.json`: generated anti-bot product catalog derived during sync
- `src/wappalyzer_pure/data/antibot/anti_bot_aliases_data.json`: generated canonical vendor/product alias map derived during sync
- `src/wappalyzer_pure/data/antibot/anti_bot_catalog_rules.json`: JSON rules used to derive anti-bot behaviors from synced products
- `src/wappalyzer_pure/data/antibot/anti_bot_alias_rules.json`: JSON rules used to canonicalize vendor and product aliases
- `src/wappalyzer_pure/data/antibot/anti_bot_signals_data.json`: curated response-evidence rules for cookies, headers, body markers, and scripts
- `src/wappalyzer_pure/data/security/security_headers_data.json`: tracked security header names
- `.github/data/source_metadata.json`: repository metadata with upstream source snapshots plus hashes and counts for the curated anti-bot rule files

This split is intentional:

- fingerprint freshness comes from syncing upstream sources
- anti-bot product detection is generated from those synced sources
- anti-bot canonical labels are generated from the synced anti-bot catalog plus a small JSON alias ruleset
- only response-evidence matching and alias overrides remain curated

The repository metadata file records:

- upstream repos, refs, commits, and sync timestamps
- generated anti-bot product and alias counts
- curated anti-bot rule file hashes and entry counts

## Security Headers

The packaged security-header list currently tracks:

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

You can load your own fingerprint data:

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

That command refreshes both upstream sources, compares them, rebuilds the
default merged source, and regenerates the packaged anti-bot technology catalog
in one pass.

Refresh only one packaged upstream and write it to explicit output files:

```bash
uv run python -m wappalyzer_pure.sync_data --source enthec
uv run python -m wappalyzer_pure.sync_data --source httparchive
```

## Upstream

This package is a pure-Python implementation inspired by
`projectdiscovery/wappalyzergo` and uses vendored fingerprint data derived from
`enthec/webappanalyzer` and `HTTPArchive/wappalyzer`.
