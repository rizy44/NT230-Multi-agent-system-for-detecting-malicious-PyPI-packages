# CodeBERT Classifier

This folder is the first-stage classifier workspace for the LAMPS replica. It trains a CodeBERT binary classifier on the downloaded project dataset.

## 1. Prepare Train/Val/Test Splits

From the project root:

```powershell
python -m lamps.main prepare-codebert-splits `
  --csv .\dataset\D2-6000snippets.csv `
  --out-dir .\CodeBERT_Classifier\data `
  --code-column "Setup.py"
```

This writes:

```text
CodeBERT_Classifier/data/train.jsonl
CodeBERT_Classifier/data/val.jsonl
CodeBERT_Classifier/data/test.jsonl
```

Each row follows the original project format:

```json
{"idx": "0", "func": "python source code here", "target": 0}
{"idx": "1", "func": "python source code here", "target": 1}
```

## 2. Train

```powershell
python -m lamps.main train-codebert `
  --train .\CodeBERT_Classifier\data\train.jsonl `
  --val .\CodeBERT_Classifier\data\val.jsonl `
  --test .\CodeBERT_Classifier\data\test.jsonl `
  --output-dir .\CodeBERT_Classifier\checkpoint
```

Defaults follow the paper/repo:

- base model: `microsoft/codebert-base`
- block size: `400`
- train batch size: `16`
- eval batch size: `64`
- learning rate: `2e-5`
- epochs: `5`
- seed: `123456`

## 3. Use Checkpoint in LAMPS

Set `.env`:

```env
CODEBERT_MODEL_PATH=CodeBERT_Classifier/checkpoint
```

Then scan with:

```powershell
python -m lamps.main scan --archive .\samples\package.tar.gz --classifier auto
```

If the checkpoint is valid, `auto` uses CodeBERT. If not, it falls back to heuristic mode.
