# MCP Server Implementation Tasks

Follow these tasks in order. Use TDD: write each test first, run it to see the expected failure, then implement minimal code.

## Task 1: Add MCP Dependencies

**Files:**

- Modify: `requirements.txt`
- Modify: `pyproject.toml`

- [ ] **Step 1: Add dependency entries**

Add `mcp` to `requirements.txt` and project dependencies in `pyproject.toml`.

- [ ] **Step 2: Verify dependency metadata**

Run:

```powershell
python -m pip install -r requirements.txt
```

Expected: dependencies install or report environment-specific CUDA/torch issues. Do not use `py`.

## Task 2: Define MCP Tool Schemas

**Files:**

- Create: `lamps_mcp/__init__.py`
- Create: `lamps_mcp/schemas.py`
- Test: `tests/test_mcp_tools.py`

- [ ] **Step 1: Write failing schema test**

```python
def test_scan_archive_args_defaults():
    from lamps_mcp.schemas import ScanArchiveArgs

    args = ScanArchiveArgs(archive_path="sample.tar.gz")

    assert args.archive_path == "sample.tar.gz"
    assert args.package_name == "local-archive"
    assert args.classifier == "auto"
```

Run:

```powershell
python -m pytest tests/test_mcp_tools.py::test_scan_archive_args_defaults -q
```

Expected: fail because `lamps_mcp.schemas` does not exist.

- [ ] **Step 2: Implement schemas**

Create dataclasses:

```python
from dataclasses import dataclass

@dataclass(slots=True)
class ScanPackageArgs:
    package: str
    classifier: str = "auto"

@dataclass(slots=True)
class ScanArchiveArgs:
    archive_path: str
    package_name: str = "local-archive"
    classifier: str = "auto"

@dataclass(slots=True)
class PrepareCodeBERTSplitsArgs:
    csv_path: str = "dataset/D2-6000snippets.csv"
    output_dir: str = "CodeBERT_Classifier/data"
    code_column: str = "Setup.py"
    label_column: str | None = None
    train_ratio: float = 0.8
    val_ratio: float = 0.1
    test_ratio: float = 0.1
    seed: int = 123456

@dataclass(slots=True)
class EvaluateDatasetArgs:
    dataset_path: str = "dataset/D2-6000snippets.csv"
    code_column: str = "Setup.py"
    label_column: str | None = None
    max_samples: int = 50

@dataclass(slots=True)
class TrainCodeBERTArgs:
    train_path: str = "CodeBERT_Classifier/data/train.jsonl"
    val_path: str = "CodeBERT_Classifier/data/val.jsonl"
    test_path: str = "CodeBERT_Classifier/data/test.jsonl"
    output_dir: str = "CodeBERT_Classifier/checkpoint"
```

- [ ] **Step 3: Re-run schema test**

Expected: pass.

## Task 3: Implement Tool Functions

**Files:**

- Create: `lamps_mcp/tools.py`
- Test: `tests/test_mcp_tools.py`

- [ ] **Step 1: Write failing test for report summary**

```python
def test_summarize_report_includes_report_path():
    from lamps.core.schemas import FileClassification, ScanReport
    from lamps_mcp.tools import summarize_report

    report = ScanReport(
        package="demo",
        version="1.0.0",
        verdict="malicious",
        malicious_files=["setup.py"],
        files_analyzed=1,
        file_results=[FileClassification(path="setup.py", label="malicious", score=0.9)],
        rationale="setup.py was flagged.",
        agent_trace={"fetcher": {}, "extractor": {}, "classifier": {}, "verdict": {}},
    )

    summary = summarize_report(report, "reports/demo-report.json")

    assert summary["package"] == "demo"
    assert summary["verdict"] == "malicious"
    assert summary["report_path"] == "reports/demo-report.json"
```

Run:

```powershell
python -m pytest tests/test_mcp_tools.py::test_summarize_report_includes_report_path -q
```

Expected: fail because `lamps_mcp.tools` does not exist.

- [ ] **Step 2: Implement `summarize_report`**

```python
def summarize_report(report, report_path):
    return {
        "package": report.package,
        "version": report.version,
        "verdict": report.verdict,
        "malicious_files": report.malicious_files,
        "files_analyzed": report.files_analyzed,
        "rationale": report.rationale,
        "report_path": str(report_path),
    }
```

- [ ] **Step 3: Implement tool wrappers**

Functions to add:

```python
def scan_package_tool(package: str, classifier: str = "auto") -> dict: ...
def scan_archive_tool(archive_path: str, package_name: str = "local-archive", classifier: str = "auto") -> dict: ...
def prepare_codebert_splits_tool(...) -> dict: ...
def evaluate_dataset_tool(...) -> dict: ...
def train_codebert_tool(...) -> dict: ...
def list_reports_tool(report_dir: str = "reports") -> dict: ...
def read_report_tool(report_path: str) -> dict: ...
```

Implementation rule: call existing `lamps/` functions only. Do not duplicate scanner/classifier logic.

## Task 4: Implement MCP Server Entry Point

**Files:**

- Create: `lamps_mcp/server.py`
- Modify: `README.md`

- [ ] **Step 1: Create server**

Use the MCP Python SDK with a server named `lamps-mcp`.

Expose all tools from `lamps_mcp.tools`.

- [ ] **Step 2: Add run command**

Document:

```powershell
python -m lamps_mcp.server
```

- [ ] **Step 3: Add MCP client config example**

Document a JSON config using:

```json
{
  "mcpServers": {
    "lamps": {
      "command": "python",
      "args": ["-m", "lamps_mcp.server"]
    }
  }
}
```

## Task 5: Wire Tests And Final Verification

**Files:**

- Modify: `tests/test_mcp_tools.py`

- [ ] **Step 1: Add report file tests**

Test `list_reports_tool()` and `read_report_tool()` using a temporary `reports/` directory.

- [ ] **Step 2: Run unit tests**

```powershell
python -m pytest tests/test_core_behaviors.py tests/test_mcp_tools.py -q
```

Expected: all tests pass.

- [ ] **Step 3: Smoke test MCP import**

```powershell
python -c "import lamps_mcp.server; print('mcp server import ok')"
```

Expected: prints `mcp server import ok`.

- [ ] **Step 4: Smoke test no-API scan path**

Prepare a local archive sample and run scan through tool function with `classifier="heuristic"`. Expected: no API key required.
