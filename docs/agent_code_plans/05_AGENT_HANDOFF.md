# Agent Handoff For MCP Implementation

You are implementing an MCP server around the existing LAMPS replica.

## What To Build

Create `lamps_mcp/` with:

```text
lamps_mcp/
  __init__.py
  schemas.py
  tools.py
  server.py
```

Expose these tools:

- `scan_package`
- `scan_archive`
- `prepare_codebert_splits`
- `evaluate_dataset`
- `train_codebert`
- `list_reports`
- `read_report`

## Non-Negotiable Rules

- Use `python`, not `py`.
- Do not execute package code from PyPI archives.
- Do not require LLM API key for startup, dataset preparation, heuristic evaluation, or heuristic archive scanning.
- Do not duplicate LAMPS logic. Import from `lamps/`.
- Keep return values JSON serializable.
- Write tests first in `tests/test_mcp_tools.py`.

## Useful Existing Functions

- `Settings.from_env()` from `lamps.core.config`
- `LAMPSPipeline` from `lamps.core.pipeline`
- `create_codebert_splits()` from `lamps.evaluation.prepare_dataset`
- `train_codebert()` and `CodeBERTTrainingConfig` from `lamps.evaluation.train_codebert`
- `classification_metrics()` from `lamps.evaluation.metrics`

## First Command To Run

```powershell
python -m pytest tests/test_core_behaviors.py -q
```

If this fails because dependencies are missing, install:

```powershell
python -m pip install -r requirements.txt
```

## Final Acceptance

The work is acceptable when:

- `python -m pytest tests/test_core_behaviors.py tests/test_mcp_tools.py -q` passes.
- `python -c "import lamps_mcp.server; print('mcp server import ok')"` succeeds.
- `python -m lamps_mcp.server` starts a stdio MCP server.
- At least `scan_archive` with `classifier="heuristic"` works without an API key.
