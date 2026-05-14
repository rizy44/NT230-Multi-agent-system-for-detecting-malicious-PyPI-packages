# LAMPS MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python MCP server that exposes the existing LAMPS replica as agent-callable tools for scanning PyPI packages, scanning local archives, preparing CodeBERT data, training/evaluating CodeBERT, and reading reports.

**Architecture:** Add a thin `lamps_mcp/` package that imports the existing `lamps/` modules. The MCP server must not duplicate LAMPS logic; it should validate tool arguments, call the core pipeline/evaluation functions, and return compact JSON-compatible results. Tools that can run without an LLM API must continue to work without `LLM_API_KEY`.

**Tech Stack:** Python 3.10+, MCP Python SDK, existing `lamps/` package, pytest, optional OpenAI-compatible LLM API, optional Hugging Face/torch for CodeBERT.

---

## Current Repo Context

Existing useful modules:

- `lamps/main.py` provides CLI commands.
- `lamps/core/pipeline.py` provides `LAMPSPipeline`.
- `lamps/core/config.py` provides `Settings.from_env()`.
- `lamps/evaluation/prepare_dataset.py` provides `csv_to_jsonl()` and `create_codebert_splits()`.
- `lamps/evaluation/train_codebert.py` provides `train_codebert()`.
- `lamps/evaluation/metrics.py` provides metric calculation.
- `CodeBERT_Classifier/data/` already contains split JSONL files.

New MCP package:

```text
lamps_mcp/
  __init__.py
  server.py
  tools.py
  schemas.py
```

New tests:

```text
tests/test_mcp_tools.py
```

New docs:

```text
docs/agent_code_plans/
```

## Server Behavior

The server exposes tools through MCP and delegates work to existing LAMPS code:

- `scan_package` calls `LAMPSPipeline.scan_package()`.
- `scan_archive` calls `LAMPSPipeline.scan_archive()`.
- `prepare_codebert_splits` calls `create_codebert_splits()`.
- `evaluate_dataset` runs the existing heuristic evaluation path or a shared helper extracted from `lamps/main.py`.
- `train_codebert` calls `train_codebert()` with explicit paths.
- `list_reports` and `read_report` inspect JSON files under `REPORT_DIR`.

The MCP layer must return dictionaries and strings that are JSON serializable.

## Out Of Scope For First MCP Version

- Full RAG baseline.
- MPHunter integration.
- Running untrusted package code.
- Long-running job queue or web dashboard.
- Automatic installation of Python, CUDA, or model dependencies.

## Default Paths

- Dataset CSV: `dataset/D2-6000snippets.csv`
- CodeBERT splits: `CodeBERT_Classifier/data`
- CodeBERT checkpoint: `CodeBERT_Classifier/checkpoint`
- Reports: `reports`

## Runtime Assumptions

- Use `python`, not `py`.
- If `LLM_API_KEY` is missing, scan tools still work with deterministic rationale or heuristic classifier.
- Training CodeBERT may require GPU and network access to download `microsoft/codebert-base`.
