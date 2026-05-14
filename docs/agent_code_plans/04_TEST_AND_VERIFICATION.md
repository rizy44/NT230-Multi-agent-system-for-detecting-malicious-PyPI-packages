# MCP Server Test And Verification Plan

Use `python`, not `py`.

## Unit Tests

Run:

```powershell
python -m pytest tests/test_core_behaviors.py tests/test_mcp_tools.py -q
```

Expected:

- File filtering tests pass.
- Safe archive extraction tests pass.
- Heuristic classifier tests pass.
- Verdict policy tests pass.
- CodeBERT dataset split tests pass.
- MCP tool wrapper tests pass.

## Dataset Split Verification

Run:

```powershell
python -m lamps.main prepare-codebert-splits `
  --csv .\dataset\D2-6000snippets.csv `
  --out-dir .\CodeBERT_Classifier\data `
  --code-column "Setup.py"
```

Expected output shape:

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

Exact counts may differ if the downloaded CSV differs from the paper's final dataset.

## Heuristic Evaluation Verification

Run:

```powershell
python -m lamps.main evaluate `
  --dataset .\dataset\D2-6000snippets.csv `
  --code-column "Setup.py" `
  --max-samples 50
```

Expected:

- JSON metrics printed.
- Includes `accuracy`, `precision`, `recall`, `f1`, `balanced_accuracy`, `confusion_matrix`.
- No LLM API key required.

## MCP Import Verification

Run:

```powershell
python -c "import lamps_mcp.server; print('mcp server import ok')"
```

Expected:

```text
mcp server import ok
```

## MCP Server Manual Start

Run:

```powershell
python -m lamps_mcp.server
```

Expected:

- Server starts and waits on stdio.
- It should not start training automatically.
- It should not require `LLM_API_KEY` at startup.

## CodeBERT Training Verification

Run only after dependencies and GPU/CUDA are visible to Python:

```powershell
python -c "import torch; print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'no cuda')"
```

Then:

```powershell
python -m lamps.main train-codebert `
  --train .\CodeBERT_Classifier\data\train.jsonl `
  --val .\CodeBERT_Classifier\data\val.jsonl `
  --test .\CodeBERT_Classifier\data\test.jsonl `
  --output-dir .\CodeBERT_Classifier\checkpoint
```

Expected:

- Downloads `microsoft/codebert-base` if not cached.
- Trains for 5 epochs.
- Writes a valid Hugging Face checkpoint under `CodeBERT_Classifier/checkpoint`.
- `--classifier auto` then chooses CodeBERT instead of heuristic.
