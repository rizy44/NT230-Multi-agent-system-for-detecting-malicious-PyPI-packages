# MCP Tool Contracts

This file defines the exact tools the MCP server should expose.

## Tool: `scan_package`

Purpose: Scan a package from PyPI without installing or executing it.

Input:

```json
{
  "package": "requests",
  "classifier": "auto"
}
```

Rules:

- `package` is required.
- `classifier` must be one of `auto`, `codebert`, `heuristic`; default is `auto`.
- Must call `LAMPSPipeline(Settings.from_env(), classifier_mode=classifier).scan_package(package)`.

Output:

```json
{
  "package": "requests",
  "version": "2.32.0",
  "verdict": "benign",
  "malicious_files": [],
  "files_analyzed": 12,
  "rationale": "All analyzed Python files were classified as benign.",
  "report_path": "reports/requests-report.json"
}
```

## Tool: `scan_archive`

Purpose: Scan a local `.tar.gz`, `.zip`, or `.whl` archive.

Input:

```json
{
  "archive_path": "samples/demo.tar.gz",
  "package_name": "demo",
  "classifier": "heuristic"
}
```

Rules:

- `archive_path` is required.
- `package_name` defaults to `local-archive`.
- `classifier` defaults to `auto`.
- Must never execute extracted code.

Output: same summary shape as `scan_package`.

## Tool: `prepare_codebert_splits`

Purpose: Convert the project CSV dataset into `train.jsonl`, `val.jsonl`, `test.jsonl`.

Input:

```json
{
  "csv_path": "dataset/D2-6000snippets.csv",
  "output_dir": "CodeBERT_Classifier/data",
  "code_column": "Setup.py",
  "label_column": "Label",
  "train_ratio": 0.8,
  "val_ratio": 0.1,
  "test_ratio": 0.1,
  "seed": 123456
}
```

Output:

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

## Tool: `evaluate_dataset`

Purpose: Evaluate current heuristic classifier on a CSV dataset.

Input:

```json
{
  "dataset_path": "dataset/D2-6000snippets.csv",
  "code_column": "Setup.py",
  "label_column": "Label",
  "max_samples": 50
}
```

Output:

```json
{
  "accuracy": 0.84,
  "precision": 0.79,
  "recall": 0.91,
  "f1": 0.85,
  "balanced_accuracy": 0.84,
  "confusion_matrix": {
    "tp": 21,
    "tn": 21,
    "fp": 4,
    "fn": 4
  }
}
```

## Tool: `train_codebert`

Purpose: Start CodeBERT fine-tuning from prepared JSONL splits.

Input:

```json
{
  "train_path": "CodeBERT_Classifier/data/train.jsonl",
  "val_path": "CodeBERT_Classifier/data/val.jsonl",
  "test_path": "CodeBERT_Classifier/data/test.jsonl",
  "output_dir": "CodeBERT_Classifier/checkpoint"
}
```

Output:

```json
{
  "eval_accuracy": 0.96,
  "eval_precision": 0.95,
  "eval_recall": 0.97,
  "eval_f1": 0.96,
  "eval_balanced_accuracy": 0.96
}
```

Rules:

- This is potentially long-running.
- Use existing `CodeBERTTrainingConfig`.
- Do not require LLM API key.

## Tool: `list_reports`

Purpose: List generated report JSON files.

Input:

```json
{
  "report_dir": "reports"
}
```

Output:

```json
{
  "reports": [
    {
      "path": "reports/demo-report.json",
      "package": "demo",
      "verdict": "malicious"
    }
  ]
}
```

## Tool: `read_report`

Purpose: Read a specific report JSON file.

Input:

```json
{
  "report_path": "reports/demo-report.json"
}
```

Output: full report JSON.
