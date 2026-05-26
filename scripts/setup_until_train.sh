#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"
DATASET_PATH="${DATASET_PATH:-./dataset/D2-6000snippets.csv}"
CODE_COLUMN="${CODE_COLUMN:-Setup.py}"
CODEBERT_DATA_DIR="${CODEBERT_DATA_DIR:-./CodeBERT_Classifier/data}"
CODEBERT_CHECKPOINT_DIR="${CODEBERT_CHECKPOINT_DIR:-./CodeBERT_Classifier/checkpoint}"

echo "==> Project root: $PROJECT_ROOT"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: '$PYTHON_BIN' was not found. Install Python 3.10+ first, or set PYTHON_BIN=/path/to/python." >&2
  exit 1
fi

if [ ! -f "$DATASET_PATH" ]; then
  echo "ERROR: Dataset not found at $DATASET_PATH" >&2
  exit 1
fi

echo "==> Creating virtual environment: $VENV_DIR"
"$PYTHON_BIN" -m venv "$VENV_DIR"

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "==> Upgrading pip tooling"
python -m pip install --upgrade pip setuptools wheel

echo "==> Installing Python dependencies"
pip install -r requirements.txt

if [ ! -f .env ] && [ -f .env.example ]; then
  echo "==> Creating .env from .env.example"
  cp .env.example .env
else
  echo "==> Keeping existing .env"
fi

echo "==> Preparing CodeBERT train/val/test splits"
python -m lamps.main prepare-codebert-splits \
  --csv "$DATASET_PATH" \
  --out-dir "$CODEBERT_DATA_DIR" \
  --code-column "$CODE_COLUMN"

cat <<EOF

==> Setup is ready.

Before training, edit .env if needed:
  nano .env

Then start CodeBERT training with:
  source "$VENV_DIR/bin/activate"
  python -m lamps.main train-codebert \\
    --train "$CODEBERT_DATA_DIR/train.jsonl" \\
    --val "$CODEBERT_DATA_DIR/val.jsonl" \\
    --test "$CODEBERT_DATA_DIR/test.jsonl" \\
    --output-dir "$CODEBERT_CHECKPOINT_DIR"

EOF
