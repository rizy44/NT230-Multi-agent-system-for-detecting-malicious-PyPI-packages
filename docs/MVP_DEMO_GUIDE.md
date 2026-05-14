# LAMPS MCP MVP Demo Guide

This guide shows how to run the current MVP for a short demo. The MVP includes:

- Static scanning for local archives and PyPI packages.
- Heuristic classifier fallback without `LLM_API_KEY`.
- Dataset split preparation for CodeBERT.
- Heuristic dataset evaluation.
- MCP stdio server exposing the LAMPS tools.
- JSON report listing and reading.

CodeBERT training is available but optional for the MVP demo because it can take a long time and may need GPU/network access.

## 1. Prerequisites

Use Windows PowerShell from the project root:

```powershell
cd "<project-root>"
```

Confirm Python 3.10+:

```powershell
python --version
```

Expected:

```text
Python 3.10.11
```

If `python` is not found but Python is installed, run commands with the full path instead:

```powershell
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python310\python.exe" --version
```

## 2. Install Dependencies

Create a virtual environment:

```powershell
python -m venv .venv
```

Install dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The MCP dependency is included in `requirements.txt`.

If the project path contains Vietnamese characters and pip prints encoding warnings, run:

```powershell
$env:PYTHONUTF8 = "1"
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 3. Verify The MVP

Run the test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_core_behaviors.py tests/test_mcp_tools.py -q
```

Expected:

```text
16 passed
```

Check MCP server import:

```powershell
.\.venv\Scripts\python.exe -c "import lamps_mcp.server; print('mcp server import ok')"
```

Expected:

```text
mcp server import ok
```

## 4. Demo A: Scan A Local Archive Without API Key

Create a tiny local archive containing suspicious Python code:

```powershell
New-Item -ItemType Directory -Force demo_samples\demo_pkg | Out-Null
Set-Content -Path demo_samples\demo_pkg\setup.py -Value "import base64, subprocess`nsubprocess.Popen(base64.b64decode('YWJj'))"
tar -czf demo_samples\demo_pkg.tar.gz -C demo_samples demo_pkg
```

Run the scan with the heuristic classifier:

```powershell
.\.venv\Scripts\python.exe -m lamps.main scan --archive .\demo_samples\demo_pkg.tar.gz --package-name demo-pkg --classifier heuristic
```

Expected result:

- JSON output is printed.
- `verdict` is `malicious`.
- `malicious_files` includes `demo_pkg/setup.py`.
- A report is written under `reports/demo-pkg-report.json`.

This demo does not require `LLM_API_KEY`.

## 5. Demo B: Evaluate The Dataset Heuristically

Run a small evaluation sample:

```powershell
.\.venv\Scripts\python.exe -m lamps.main evaluate --dataset .\dataset\D2-6000snippets.csv --code-column "Setup.py" --max-samples 50
```

Expected output includes:

- `accuracy`
- `precision`
- `recall`
- `f1`
- `balanced_accuracy`
- `confusion_matrix`

## 6. Demo C: Prepare CodeBERT Splits

Generate train/validation/test JSONL files into a demo output directory:

```powershell
.\.venv\Scripts\python.exe -m lamps.main prepare-codebert-splits --csv .\dataset\D2-6000snippets.csv --out-dir .\demo_samples\codebert_data --code-column "Setup.py"
```

Expected output is a JSON summary with counts like:

```json
{
  "total": 6000,
  "train": 4800,
  "val": 600,
  "test": 600,
  "benign": 3000,
  "malicious": 3000
}
```

Exact counts can differ if the CSV differs from the expected dataset.

## 7. Demo D: Start The MCP Server

Start the stdio MCP server:

```powershell
.\.venv\Scripts\python.exe -m lamps_mcp.server
```

Expected:

- The process stays running and waits for MCP client messages over stdio.
- Startup does not require `LLM_API_KEY`.
- It does not start scans or training automatically.

Use this client config in an MCP-compatible client:

```json
{
  "mcpServers": {
    "lamps": {
      "command": ".\\.venv\\Scripts\\python.exe",
      "args": ["-m", "lamps_mcp.server"]
    }
  }
}
```

Available MCP tools:

- `scan_package`
- `scan_archive`
- `prepare_codebert_splits`
- `evaluate_dataset`
- `train_codebert`
- `list_reports`
- `read_report`

## 8. Suggested MCP Demo Calls

Call `scan_archive`:

```json
{
  "archive_path": "demo_samples/demo_pkg.tar.gz",
  "package_name": "demo-pkg",
  "classifier": "heuristic"
}
```

Call `list_reports`:

```json
{
  "report_dir": "reports"
}
```

Call `read_report`:

```json
{
  "report_path": "reports/demo-pkg-report.json"
}
```

## 9. Optional: LLM And CodeBERT

For API-generated verdict explanations, copy `.env.example` to `.env` and set:

```text
LLM_API_KEY=your_api_key_here
```

For CodeBERT training:

```powershell
.\.venv\Scripts\python.exe -m lamps.main train-codebert --train .\CodeBERT_Classifier\data\train.jsonl --val .\CodeBERT_Classifier\data\val.jsonl --test .\CodeBERT_Classifier\data\test.jsonl --output-dir .\CodeBERT_Classifier\checkpoint
```

Training may download `microsoft/codebert-base`, may take a long time, and may need GPU/CUDA for a smooth demo.

## 10. Troubleshooting

If PowerShell blocks venv activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

If `python` resolves differently between terminals, use the full Python path:

```powershell
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python310\python.exe" -m venv .venv
.\.venv\Scripts\python.exe -m pytest tests/test_core_behaviors.py tests/test_mcp_tools.py -q
```

If `LLM_API_KEY` is missing, use:

```powershell
--classifier heuristic
```

The static archive scanner does not install, import, or execute package code.
