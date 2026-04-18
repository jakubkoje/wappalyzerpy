# Dataset Example

This folder contains a copied sample dataset input and a batch runner for
producing `wappalyzer-pure` outputs at scale.

Included files:

- `train_5k.csv`: copied from the external sample input you provided
- `run_dataset_scan.py`: scans the CSV and writes both JSONL and CSV outputs

Run from the project root:

```bash
uv sync
uv run python examples/dataset/run_dataset_scan.py
```

Useful variants:

```bash
uv run python examples/dataset/run_dataset_scan.py --limit 100
uv run python examples/dataset/run_dataset_scan.py --workers 20 --timeout 15
uv run python examples/dataset/run_dataset_scan.py --insecure-tls
uv run python examples/dataset/run_dataset_scan.py --fetch-scripts same-origin
uv run python examples/dataset/run_dataset_scan.py --headless --workers 5
uv run python examples/dataset/run_dataset_scan.py --deep-headless --workers 5
```

Outputs:

- `examples/dataset/output/results.jsonl`
  - one JSON object per input URL
  - stores the full `AnalysisResult.to_dict(...)` payload under `wappalyzer`
- `examples/dataset/output/results.csv`
  - flattened summary row per URL
  - useful for quick filtering, aggregation, and notebook work

The JSONL row shape is:

```json
{
  "source": "https://example.com",
  "wappalyzer": {
    "target_url": "https://example.com",
    "final_url": "https://example.com",
    "status_code": 200,
    "technologies": [],
    "anti_bot_findings": [],
    "security_headers": [],
    "artifacts": null,
    "fetch_info": null,
    "fetch_failure": null
  }
}
```
