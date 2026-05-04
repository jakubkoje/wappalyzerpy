# wappalyzer-pure

Pure-Python website technology detection from HTTP responses.

`wappalyzer-pure` fingerprints technologies from headers, cookies, raw HTML,
`<meta>` tags, `<script src>` URLs, inline JavaScript, and optionally bounded
external JavaScript files or a Playwright-rendered page. It is library-first,
with a small CLI for ad hoc scans and dataset work.

## Contents

- [Features](#features)
- [Install](#install)
- [Quickstart](#quickstart)
- [Fetch and Browser Modes](#fetch-and-browser-modes)
- [Anti-Bot Findings](#anti-bot-findings)
- [CLI](#cli)
- [Packaged Data](#packaged-data)
- [Public API](#public-api)
- [Result Objects](#result-objects)
- [Custom Data](#custom-data)
- [Development](#development)
- [Upstream](#upstream)

## Features

- Pure Python package, no Go bridge or native build step.
- Analyze already-fetched responses with `analyze_response(...)`.
- Fetch and fingerprint URLs with `analyze_url(...)`.
- Tune retries, partial-read salvage, TLS verification, and request header profile with `FetchOptions`.
- Detect technologies from headers, cookies, HTML, meta tags, script URLs, inline scripts, and optional external scripts.
- Use a merged default fingerprint source, or inspect `enthec` and `httparchive` separately.
- Return structured dataclass results instead of raw strings.
- Return structured fetch failures instead of aborting crawls on transient network errors.
- Report security-relevant technologies and common security headers separately.
- Detect anti-bot and CAPTCHA evidence with explicit matched artifacts.
- Optionally render pages with Playwright for JavaScript-heavy sites.
- Optionally collect deeper browser-only anti-bot signals such as runtime globals, iframe URLs, resource URLs, and browser cookies.
- Run lightweight active HTTP probes with `probe_url(...)`.

## Install

For local development in this repository:

```bash
uv sync
```

For headless browser scans:

```bash
uv sync --extra headless
uv run playwright install chromium
```

The package requires Python `>=3.11`. The only optional runtime dependency is
Playwright through the `headless` extra.

## Quickstart

For runnable examples, see [examples/README.md](examples/README.md).

### Scan a URL

```python
from wappalyzer_pure import analyze_url

result = analyze_url("https://example.com")

print(result.status_code)
print(result.final_url)
print([tech.display_name for tech in result.technologies])
print([tech.name for tech in result.security_technologies])
print([finding.vendor for finding in result.anti_bot_findings])
print(result.fetch_info)
print(result.fetch_failure)
```

### Analyze an Existing Response

```python
from wappalyzer_pure import analyze_response

headers = {
    "Server": "cloudflare",
    "Content-Type": "text/html; charset=utf-8",
    "Set-Cookie": ["__cf_bm=example"],
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

### Tune Fetching

```python
from wappalyzer_pure import FetchHeaderProfile, FetchOptions, FetchTLSMode, analyze_url

result = analyze_url(
    "https://example.com",
    fetch_options=FetchOptions(
        timeout=15.0,
        retries=1,
        retry_backoff_seconds=0.25,
        allow_partial_reads=True,
        tls_mode=FetchTLSMode.STRICT,
        header_profile=FetchHeaderProfile.BROWSER,
    ),
)

print(result.ok)
print(result.fetch_info)
```

### Handle Fetch Failures

```python
from wappalyzer_pure import FetchOptions, analyze_url

result = analyze_url(
    "https://expired.badssl.com",
    fetch_options=FetchOptions(retries=0),
)

if not result.ok and result.fetch_failure is not None:
    print(result.fetch_failure.category)
    print(result.fetch_failure.message)
```

### Choose a Fingerprint Source

`merged` is the default packaged source. To inspect one upstream directly, pass
a source explicitly.

```python
from wappalyzer_pure import FingerprintDataSource, analyze_url

result = analyze_url(
    "https://example.com",
    source=FingerprintDataSource.HTTPARCHIVE,
)
```

<details>
<summary>More quickstart examples</summary>

### Fetch Bounded External Scripts

Inline `<script>` contents are matched automatically. External script fetching is
opt-in and currently supports same-origin script URLs.

```python
from wappalyzer_pure import ScriptAnalysisOptions, ScriptFetchPolicy, analyze_url

result = analyze_url(
    "https://example.com",
    script_analysis=ScriptAnalysisOptions(
        fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
        max_external_scripts=8,
        max_bytes_per_script=256_000,
        max_total_script_bytes=1_048_576,
    ),
)

print([tech.display_name for tech in result.technologies])
```

If you already fetched the page yourself, pass `response_url=...` so relative
`<script src>` values can be resolved correctly.

```python
from wappalyzer_pure import ScriptAnalysisOptions, ScriptFetchPolicy, analyze_response

result = analyze_response(
    headers,
    body,
    response_url="https://example.com/app",
    script_analysis=ScriptAnalysisOptions(
        fetch_policy=ScriptFetchPolicy.SAME_ORIGIN,
    ),
)
```

### Render in a Headless Browser

```python
from wappalyzer_pure import HeadlessOptions, HeadlessWaitUntil, analyze_url

result = analyze_url(
    "https://example.com",
    headless_options=HeadlessOptions(
        wait_until=HeadlessWaitUntil.LOAD,
        post_load_delay_seconds=0.5,
    ),
)

print(result.fetch_info.transport if result.fetch_info else None)
print([finding.vendor for finding in result.anti_bot_findings])
```

### Capture Browser-Only Anti-Bot Signals

```python
from wappalyzer_pure import DeepHeadlessOptions, HeadlessOptions, analyze_url

result = analyze_url(
    "https://example.com",
    headless_options=HeadlessOptions(),
    deep_headless=DeepHeadlessOptions(),
    capture_artifacts=True,
)

print(result.artifacts.runtime_markers if result.artifacts else ())
print([finding.vendor for finding in result.anti_bot_findings])
```

### Run Active HTTP Probes

```python
from wappalyzer_pure import ProbeOptions, probe_url

result = probe_url(
    "https://example.com",
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

### Capture Lightweight Response Artifacts

```python
from wappalyzer_pure import ArtifactCaptureOptions, analyze_url

result = analyze_url(
    "https://example.com",
    capture_artifacts=ArtifactCaptureOptions(body_excerpt_chars=128),
)

print(result.artifacts.body_sha256 if result.artifacts else None)
print(result.artifacts.script_sources if result.artifacts else ())
```

</details>

## Fetch and Browser Modes

`analyze_url(...)` and `probe_url(...)` use a shared `urllib` fetch layer. HTTP
error responses such as `403` and `429` are still analyzed when a body is
available. Transport failures become `AnalysisResult.fetch_failure`, retries are
controlled by `FetchOptions.retries`, incomplete bodies can be salvaged with
`allow_partial_reads`, TLS is strict by default, and the default header profile
is browser-like.

Headless mode is disabled by default. When `headless_options` is provided,
`analyze_url(...)` switches to Playwright, renders the page, fingerprints the
rendered DOM from `page.content()`, and preserves the normal `AnalysisResult`
shape. `probe_url(...)` remains HTTP-only.

Deep headless mode is enabled with `deep_headless=True` or
`deep_headless=DeepHeadlessOptions(...)`. It implies headless rendering when
`headless_options` is omitted and feeds browser cookies, iframe/script URLs,
resource URLs, and runtime globals into the anti-bot and artifact pipeline.

Dataset scans can use HTTP-first fallback:

```bash
uv run python examples/dataset/run_dataset_scan.py --headless-on-http-miss --workers 5
```

That mode keeps the cheap HTTP path when response evidence is enough, then
reruns only anti-bot misses with deep headless analysis.

<details>
<summary>Headless install and CLI examples</summary>

```bash
uv sync --extra headless
uv run playwright install chromium
```

```bash
uv run wappalyzer-pure scan https://example.com \
  --headless \
  --headless-wait-until load \
  --headless-post-load-delay 0.5 \
  --json
```

```bash
uv run wappalyzer-pure scan https://example.com \
  --deep-headless \
  --artifacts \
  --json
```

</details>

## Anti-Bot Findings

`AnalysisResult.anti_bot_findings` exposes explicit scraping-protection findings
instead of forcing callers to infer them from generic technology names.

The anti-bot layer is conservative by default: generic CDN presence alone does
not become an anti-bot finding. It combines curated response-signal rules with a
generated anti-bot technology catalog derived from the synced fingerprints, then
normalizes vendors and products to canonical labels.

Evidence can come from cookies, headers, body markers, script URLs, fetched
script contents, matched technologies, status codes, redirects, browser resource
URLs, browser cookies, and runtime markers. Each finding includes exact matched
artifacts through `AntiBotEvidence`.

As of the packaged data snapshot from `2026-05-04T07:42:13Z`, the generated
anti-bot catalog contains 38 technology entries, with 47 vendor aliases and 40
product aliases. The curated response-signal rules cover 12 vendors and 16
behavior labels.

<details>
<summary>Anti-bot data files and example</summary>

Data sources behind this layer:

- `src/wappalyzer_pure/data/fingerprints/`: synced product fingerprints
- `src/wappalyzer_pure/data/categories/`: synced categories
- `src/wappalyzer_pure/data/antibot/anti_bot_technologies_data.json`: generated anti-bot product catalog
- `src/wappalyzer_pure/data/antibot/anti_bot_aliases_data.json`: generated anti-bot alias map
- `src/wappalyzer_pure/data/antibot/anti_bot_catalog_rules.json`: anti-bot catalog derivation rules
- `src/wappalyzer_pure/data/antibot/anti_bot_alias_rules.json`: anti-bot alias rules
- `src/wappalyzer_pure/data/antibot/anti_bot_signals_data.json`: curated response-signal rules

Example:

```python
from wappalyzer_pure import analyze_response

result = analyze_response(
    {
        "Server": "cloudflare",
        "CF-Ray": "abc123",
        "Set-Cookie": ["__cf_bm=opaque; Path=/; HttpOnly"],
    },
    "<html></html>",
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

Canonicalization examples:

- `Akamai Bot Manager` findings normalize to vendor `Akamai`.
- `HUMAN / PerimeterX` findings normalize to vendor `HUMAN`.
- Raw matched values stay available in `AntiBotEvidence`.

</details>

## CLI

```bash
uv run wappalyzer-pure scan https://example.com
uv run wappalyzer-pure scan https://example.com --json
uv run wappalyzer-pure scan https://example.com --json --security-only
uv run wappalyzer-pure scan https://example.com --fetch-scripts same-origin
uv run wappalyzer-pure scan https://example.com --json --artifacts
uv run wappalyzer-pure scan https://example.com --source httparchive
uv run wappalyzer-pure scan https://example.com --headless --json
uv run wappalyzer-pure scan https://example.com --deep-headless --artifacts --json
uv run wappalyzer-pure probe https://example.com --json
uv run wappalyzer-pure probe https://example.com --no-browser-like
```

<details>
<summary>CLI flags</summary>

Shared scan and probe flags:

- `--source {merged,enthec,httparchive}`
- `--timeout`
- `--retries`
- `--retry-backoff`
- `--header-profile {browser,library}`
- `--insecure-tls`
- `--no-partial-reads`
- `--user-agent`
- `--fetch-scripts {off,same-origin}`
- `--max-external-scripts`
- `--max-bytes-per-script`
- `--max-total-script-bytes`
- `--artifacts`
- `--body-excerpt-chars`
- `--json`

Scan-only flags:

- `--security-only`
- `--headless`
- `--deep-headless`
- `--headless-browser {chromium,firefox,webkit}`
- `--headless-timeout`
- `--headless-wait-until {commit,domcontentloaded,load,networkidle}`
- `--headless-post-load-delay`
- `--headless-simulate-interaction`

Probe-only flags:

- `--no-repeat`
- `--no-cookie-follow-up`
- `--no-browser-like`

Dataset runner examples:

```bash
uv run python examples/dataset/run_dataset_scan.py --limit 100
uv run python examples/dataset/run_dataset_scan.py --workers 20 --timeout 15
uv run python examples/dataset/run_dataset_scan.py --fetch-scripts same-origin
uv run python examples/dataset/run_dataset_scan.py --headless-on-http-miss --headless-wait-until domcontentloaded
```

</details>

## Packaged Data

The package ships three fingerprint sources:

- `merged`: default source generated from both upstreams
- `enthec`: source-specific view from `enthec/webappanalyzer`
- `httparchive`: source-specific view from `HTTPArchive/wappalyzer`

Packaged data snapshot:

| Source | Technologies | Categories | Commit |
| --- | ---: | ---: | --- |
| `merged` | 7,524 | 108 | generated from `enthec` and `httparchive` |
| `enthec` | 7,518 | 108 | `c2855b4652b4a205c55a7fa7cbf6f02d0d6dd82b` |
| `httparchive` | 3,993 | 108 | `4c736a0b5c5f03f466250839fae5f37053a03cbf` |

Snapshot timestamp: `2026-05-04T07:42:13Z`.

The repository also includes a scheduled GitHub workflow that refreshes
fingerprints weekly, opens an update PR when data changes, bumps the patch
version, and triggers a release workflow after merge.

<details>
<summary>Packaged data layout</summary>

- `src/wappalyzer_pure/data/fingerprints/`: synced Wappalyzer-style technology fingerprints
- `src/wappalyzer_pure/data/categories/`: synced category metadata
- `src/wappalyzer_pure/data/antibot/anti_bot_technologies_data.json`: generated anti-bot product catalog
- `src/wappalyzer_pure/data/antibot/anti_bot_aliases_data.json`: generated canonical vendor/product alias map
- `src/wappalyzer_pure/data/antibot/anti_bot_catalog_rules.json`: JSON rules used to derive anti-bot behaviors from synced products
- `src/wappalyzer_pure/data/antibot/anti_bot_alias_rules.json`: JSON rules used to canonicalize aliases
- `src/wappalyzer_pure/data/antibot/anti_bot_signals_data.json`: curated response-evidence rules
- `src/wappalyzer_pure/data/security/security_headers_data.json`: tracked security header names
- `.github/data/source_metadata.json`: upstream snapshots, counts, hashes, and rule metadata

Tracked security headers:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Resource-Policy`

</details>

## Public API

The package exports:

```python
from wappalyzer_pure import (
    AnalysisResult,
    AntiBotEvidence,
    AntiBotFinding,
    AppInfo,
    ArtifactCaptureOptions,
    BrowserSignals,
    CapturedHeader,
    DataLoadError,
    DeepHeadlessOptions,
    FetchFailure,
    FetchHeaderProfile,
    FetchInfo,
    FetchOptions,
    FetchTLSMode,
    FingerprintDataSource,
    HeadlessBrowser,
    HeadlessOptions,
    HeadlessUnavailableError,
    HeadlessWaitUntil,
    PatternError,
    ProbeObservation,
    ProbeOptions,
    ProbeResult,
    ResponseArtifacts,
    SecurityHeaderStatus,
    ScriptAnalysisOptions,
    ScriptFetchPolicy,
    Technology,
    Wappalyzer,
    WappalyzerPureError,
    analyze_response,
    analyze_url,
    get_default_wappalyzer,
    probe_url,
)
```

<details>
<summary>Function signatures</summary>

```python
def analyze_url(
    url: str,
    *,
    timeout: float = 10.0,
    request_headers: Mapping[str, str] | None = None,
    user_agent: str | None = None,
    opener: urllib_request.OpenerDirector | None = None,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    script_analysis: ScriptAnalysisOptions | None = None,
    client: Wappalyzer | None = None,
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
    fetch_options: FetchOptions | None = None,
    headless_options: HeadlessOptions | None = None,
    headless_fetcher: HeadlessFetcher | None = None,
    deep_headless: bool | DeepHeadlessOptions | None = None,
) -> AnalysisResult: ...
```

Fetches a URL, fingerprints the response, and returns `AnalysisResult`.
`client` takes precedence over `source`. `deep_headless` implies headless
rendering when `headless_options` is omitted.

```python
def analyze_response(
    headers: Mapping[str, str | bytes | Sequence[str | bytes]],
    body: bytes | bytearray | memoryview | str,
    *,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    status_code: int | None = None,
    response_url: str | None = None,
    script_analysis: ScriptAnalysisOptions | None = None,
    script_timeout: float = 10.0,
    script_request_headers: Mapping[str, str] | None = None,
    script_opener: urllib_request.OpenerDirector | None = None,
    client: Wappalyzer | None = None,
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
    browser_signals: BrowserSignals | None = None,
) -> AnalysisResult: ...
```

Fingerprints an already-fetched response. `response_url` is required when
external script fetching is enabled.

```python
def probe_url(
    url: str,
    *,
    timeout: float = 10.0,
    request_headers: Mapping[str, str] | None = None,
    user_agent: str | None = DEFAULT_USER_AGENT,
    opener: urllib_request.OpenerDirector | None = None,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    script_analysis: ScriptAnalysisOptions | None = None,
    client: Wappalyzer | None = None,
    probe_options: ProbeOptions | None = None,
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
    fetch_options: FetchOptions | None = None,
) -> ProbeResult: ...
```

Runs active HTTP request profiles and returns one `ProbeObservation` per
executed request. The current observations are `initial`, `repeat`,
`cookie_follow_up`, and `browser_like`.

</details>

<details>
<summary>Option dataclasses and enums</summary>

```python
class FingerprintDataSource(str, Enum):
    MERGED = "merged"
    ENTHEC = "enthec"
    HTTPARCHIVE = "httparchive"
```

```python
class ScriptFetchPolicy(str, Enum):
    OFF = "off"
    SAME_ORIGIN = "same-origin"

@dataclass(frozen=True, slots=True)
class ScriptAnalysisOptions:
    fetch_policy: ScriptFetchPolicy = ScriptFetchPolicy.OFF
    max_external_scripts: int = 8
    max_bytes_per_script: int = 256_000
    max_total_script_bytes: int = 1_048_576
```

```python
@dataclass(frozen=True, slots=True)
class ArtifactCaptureOptions:
    body_excerpt_chars: int = 256
    captured_at_utc: str | None = None
```

```python
class FetchHeaderProfile(str, Enum):
    LIBRARY = "library"
    BROWSER = "browser"

class FetchTLSMode(str, Enum):
    STRICT = "strict"
    INSECURE = "insecure"

@dataclass(frozen=True, slots=True)
class FetchOptions:
    timeout: float = 10.0
    retries: int = 1
    retry_backoff_seconds: float = 0.25
    allow_partial_reads: bool = True
    tls_mode: FetchTLSMode = FetchTLSMode.STRICT
    header_profile: FetchHeaderProfile = FetchHeaderProfile.BROWSER
```

```python
class HeadlessBrowser(str, Enum):
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"

class HeadlessWaitUntil(str, Enum):
    COMMIT = "commit"
    DOMCONTENTLOADED = "domcontentloaded"
    LOAD = "load"
    NETWORKIDLE = "networkidle"

@dataclass(frozen=True, slots=True)
class HeadlessOptions:
    browser: HeadlessBrowser = HeadlessBrowser.CHROMIUM
    navigation_timeout: float | None = None
    wait_until: HeadlessWaitUntil = HeadlessWaitUntil.LOAD
    post_load_delay_seconds: float = 0.5
    viewport_width: int = 1440
    viewport_height: int = 900
    locale: str = "en-US"
    simulate_interaction: bool = False
```

```python
@dataclass(frozen=True, slots=True)
class DeepHeadlessOptions:
    capture_dom_sources: bool = True
    capture_frame_sources: bool = True
    capture_resource_urls: bool = True
    capture_cookies: bool = True
    runtime_markers: tuple[str, ...] = (...)
    max_script_sources: int = 128
    max_frame_sources: int = 64
    max_resource_urls: int = 256
```

```python
@dataclass(frozen=True, slots=True)
class ProbeOptions:
    repeat_request: bool = True
    follow_up_with_cookies: bool = True
    browser_like_request: bool = True
    browser_user_agent: str | None = DEFAULT_BROWSER_USER_AGENT
```

</details>

<details>
<summary>Low-level engine</summary>

```python
from wappalyzer_pure import FingerprintDataSource, Wappalyzer

client = Wappalyzer.from_package_data()
client = Wappalyzer.from_package_data(source=FingerprintDataSource.MERGED)
client = Wappalyzer.from_package_data(source=FingerprintDataSource.HTTPARCHIVE)
client = Wappalyzer.from_json_strings(fingerprints_json, categories_json)
```

`Wappalyzer.from_json_strings(...)` derives an anti-bot technology catalog from
the supplied fingerprint and category payloads, so custom datasets still
participate in anti-bot product detection.

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

</details>

## Result Objects

`AnalysisResult` is returned by `analyze_url(...)` and `analyze_response(...)`.
`ProbeResult` is returned by `probe_url(...)`. All result objects expose
`to_dict()` for JSON-ready serialization.

<details>
<summary>Result dataclasses</summary>

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
    fetch_info: FetchInfo | None = None
    fetch_failure: FetchFailure | None = None
```

Helpers:

- `ok`: `True` when `fetch_failure is None`
- `security_technologies`: `technologies` filtered to security-relevant entries
- `to_dict(security_only: bool = False)`

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

```python
@dataclass(frozen=True, slots=True)
class SecurityHeaderStatus:
    name: str
    present: bool
    value: str | None = None
```

```python
@dataclass(frozen=True, slots=True)
class AntiBotFinding:
    vendor: str
    score: int
    confidence: str
    products: tuple[str, ...] = ()
    behaviors: tuple[str, ...] = ()
    evidence: tuple[AntiBotEvidence, ...] = ()

@dataclass(frozen=True, slots=True)
class AntiBotEvidence:
    source: str
    indicator: str
    matched_value: str | None = None
    artifact: str | None = None
```

```python
@dataclass(frozen=True, slots=True)
class FetchInfo:
    attempts: int
    partial_response: bool
    header_profile: str
    tls_mode: str
    transport: str = "http"
    browser: str | None = None
    wait_until: str | None = None

@dataclass(frozen=True, slots=True)
class FetchFailure:
    category: str
    error_type: str
    message: str
    retryable: bool
    attempts: int
```

```python
@dataclass(frozen=True, slots=True)
class ResponseArtifacts:
    captured_at_utc: str | None = None
    headers: tuple[CapturedHeader, ...] = ()
    set_cookie_values: tuple[str, ...] = ()
    script_sources: tuple[str, ...] = ()
    iframe_sources: tuple[str, ...] = ()
    fetched_script_urls: tuple[str, ...] = ()
    resource_urls: tuple[str, ...] = ()
    runtime_markers: tuple[str, ...] = ()
    browser_cookie_names: tuple[str, ...] = ()
    body_sha256: str | None = None
    body_excerpt: str | None = None

@dataclass(frozen=True, slots=True)
class CapturedHeader:
    name: str
    values: tuple[str, ...]
```

```python
@dataclass(frozen=True, slots=True)
class ProbeObservation:
    name: str
    result: AnalysisResult
    request_headers: tuple[tuple[str, str], ...] = ()
    request_cookie_names: tuple[str, ...] = ()
    response_cookie_names: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class ProbeResult:
    observations: tuple[ProbeObservation, ...] = ()
```

`ProbeObservation` exposes `redirected`, `challenge_observed`, and `throttled`.
`ProbeResult` exposes `vendors`, `challenge_observed`, and `throttled`.

</details>

<details>
<summary>Example JSON output</summary>

This is representative output from `analyze_response(...)`:

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
      "categories": ["CDN"],
      "security_relevant": true
    }
  ],
  "anti_bot_findings": [
    {
      "vendor": "Cloudflare",
      "score": 7,
      "confidence": "high",
      "products": ["Cloudflare Bot Management"],
      "behaviors": ["bot_management"],
      "evidence": [
        {
          "source": "cookie",
          "indicator": "__cf_bm",
          "matched_value": "__cf_bm",
          "artifact": "__cf_bm=example"
        }
      ]
    }
  ],
  "security_headers": [
    {
      "name": "Content-Security-Policy",
      "present": true,
      "value": "default-src 'self'"
    }
  ],
  "artifacts": null,
  "fetch_info": null,
  "fetch_failure": null
}
```

</details>

## Custom Data

You can load your own fingerprint data:

```python
import json

from wappalyzer_pure import Wappalyzer, analyze_response

fingerprints_json = json.dumps(
    {
        "apps": {
            "Cloudflare": {
                "headers": {"server": "cloudflare"},
                "cats": [31],
                "description": "Reverse proxy and CDN",
            }
        }
    }
)

categories_json = json.dumps({"31": {"name": "CDN", "priority": 1}})

client = Wappalyzer.from_json_strings(fingerprints_json, categories_json)
result = analyze_response({"Server": "cloudflare"}, b"", client=client)
print(result.to_dict())
```

## Limitations

This package intentionally stays response-first by default. It does not execute
JavaScript unless you opt into headless mode, collect browser-only signals
unless you opt into deep headless mode, or crawl arbitrary script graphs.
External script fetching is limited to explicit `<script src>` references and
is only enabled when you opt into it.

## Development

Run tests:

```bash
uv run pytest
```

Run formatting, linting, and type checking:

```bash
uv run ruff check src tests main.py examples
uv run ruff format --check src tests main.py examples
uv run ty check src tests main.py examples
```

Refresh the packaged fingerprint data manually:

```bash
uv run python -m wappalyzer_pure.sync_data
```

That command refreshes both upstream sources, compares them, rebuilds the
default merged source, and regenerates the packaged anti-bot technology catalog
and alias map in one pass.

<details>
<summary>Headless tests and targeted data refresh</summary>

To include real browser-backed headless integration tests:

```bash
uv sync --extra headless
uv run playwright install chromium
uv run pytest
```

Run only real headless browser tests:

```bash
uv run pytest -m headless_integration
```

Skip them explicitly:

```bash
uv run pytest -m "not headless_integration"
```

Refresh only one packaged upstream:

```bash
uv run python -m wappalyzer_pure.sync_data --source enthec
uv run python -m wappalyzer_pure.sync_data --source httparchive
```

</details>

## Upstream

This package is a pure-Python implementation inspired by
`projectdiscovery/wappalyzergo` and uses vendored fingerprint data derived from
`enthec/webappanalyzer` and `HTTPArchive/wappalyzer`.
