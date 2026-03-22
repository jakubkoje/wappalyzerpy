# Examples

These examples show the main supported usage patterns of `wappalyzer-pure`.

Run them from the project root after:

```bash
uv sync
```

## Offline Examples

These do not require network access.

```bash
uv run python examples/02_analyze_response.py
uv run python examples/05_capture_artifacts.py
uv run python examples/07_custom_dataset.py
uv run python examples/08_low_level_engine.py
uv run python examples/09_security_only_output.py
uv run python examples/10_analyze_response_with_response_url.py
uv run python examples/11_direct_script_fetch_helper.py
uv run python examples/12_custom_antibot_canonicalization.py
```

## Networked Examples

These fetch live pages.

```bash
uv run python examples/01_analyze_url.py https://example.com
uv run python examples/03_compare_sources.py https://example.com
uv run python examples/04_fetch_external_scripts.py https://example.com
uv run python examples/06_probe_target.py https://example.com
```

## Included Scripts

- `01_analyze_url.py`: basic live URL scan and JSON output
- `02_analyze_response.py`: analyze an already-fetched response in memory
- `03_compare_sources.py`: compare `merged`, `enthec`, and `httparchive`
- `04_fetch_external_scripts.py`: enable bounded same-origin external script fetching
- `05_capture_artifacts.py`: capture response artifacts alongside detections
- `06_probe_target.py`: run active multi-request probing
- `07_custom_dataset.py`: load a custom fingerprint dataset and use it through the public API
- `08_low_level_engine.py`: use `get_default_wappalyzer()` and the low-level engine methods directly
- `09_security_only_output.py`: serialize only security-relevant technologies
- `10_analyze_response_with_response_url.py`: analyze an already-fetched response and resolve relative script URLs with a custom opener
- `11_direct_script_fetch_helper.py`: call the external-script fetch helper directly
- `12_custom_antibot_canonicalization.py`: customize anti-bot product detection through custom fingerprints and observe canonical vendor labels
