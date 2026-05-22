# LAMPS

This workspace contains a practical replica of the LAMPS pipeline from the JSS paper and the author's `lamps-jss` repository. It keeps the four-agent structure while replacing local LLaMA 3 with an optional LLM API.

## Paper Method And Improvement Direction

The paper uses a LAMPS multi-agent design:

- Fetcher Agent downloads/extracts PyPI packages without installing them.
- Extractor Agent selects suspicious Python files and metadata.
- Classifier Agent runs a fine-tuned CodeBERT binary classifier at file level.
- Verdict Agent aggregates file predictions into a package verdict; one malicious file is enough to flag the package.

In this project, CodeBERT is kept as the baseline. The improvement path adds a stronger classical ML comparison model, `tfidf`, using character-level TF-IDF n-grams plus balanced Logistic Regression. This gives a fast, reproducible classifier that is easy to train locally and can be compared against CodeBERT before choosing `best`/`auto` for scans.

## Dataset Notes

The bundled `dataset/D2-6000snippets.csv` is usable for training and evaluation, but it is D1-style data: 6000 labeled `setup.py` snippets with a balanced benign/malicious split. It is not the true multi-file D2 package dataset described in the paper.

The checked `mal-LLM` folder also contains processed fine-tuning CSVs under `mal-LLM/RQ_experiments/finetuning_experiments/data/`. Those files are usable with `--text-column textual_description`; the JSON package files are richer but need preprocessing before direct model training.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set `LLM_API_KEY` if you want API-generated verdict explanations. Without an API key, the pipeline still runs with deterministic explanations.

## Scan

```bash
python -m lamps.main scan --package requests --classifier auto
python -m lamps.main scan --archive ./samples/package.tar.gz --package-name local-demo --classifier heuristic
```

`--classifier auto` or `--classifier best` uses a trained TF-IDF model when available, then CodeBERT when a valid checkpoint exists, and finally the transparent heuristic classifier so the demo can run on modest hardware.

After training TF-IDF, you can force that classifier explicitly:

```bash
python -m lamps.main scan --archive ./samples/package.tar.gz --package-name local-demo --classifier tfidf
```

## Evaluate

```bash
python -m lamps.main evaluate --dataset ./dataset/D2-6000snippets.csv --code-column "Setup.py" --max-samples 50
```

The default `evaluate` command uses the heuristic classifier, so it runs without any trained model. Use `--classifier tfidf` or `--classifier codebert` only after the corresponding model checkpoint exists.

## Training Workflow

You do not need to train anything just to run the demo. The system can scan with `--classifier heuristic`, and `--classifier auto` falls back safely when model checkpoints are missing.

Train models only when you want to run the experiment/comparison part of the project:

1. Keep CodeBERT as the paper baseline.
2. Train TF-IDF as the improved comparison classifier.
3. Evaluate both on the same CSV.
4. Use `compare-classifiers` to choose the best model by F1 score.

## Train TF-IDF Improvement

TF-IDF is the recommended improvement path for this project because it is fast, reproducible, and lightweight enough to train locally.

```bash
python -m lamps.main train-tfidf --dataset ./dataset/D2-6000snippets.csv --text-column "Setup.py" --output-path ./models/tfidf-malware-detector/model.joblib
python -m lamps.main evaluate --dataset ./dataset/D2-6000snippets.csv --code-column "Setup.py" --classifier tfidf
python -m lamps.main compare-classifiers --dataset ./dataset/D2-6000snippets.csv --code-column "Setup.py" --classifiers heuristic tfidf codebert
```

For the processed `mal-LLM` data:

```bash
python -m lamps.main train-tfidf --dataset ./mal-LLM/RQ_experiments/finetuning_experiments/data/train.csv --validation-dataset ./mal-LLM/RQ_experiments/finetuning_experiments/data/validation.csv --text-column textual_description --output-path ./models/tfidf-malware-detector/model.joblib
```

The command saves both `model.joblib` and a sibling `model.metrics.json` file. Set `TFIDF_MODEL_PATH` in `.env` if you want to store the model somewhere else.

`compare-classifiers` evaluates the requested classifiers on the same CSV and selects `best_classifier` by F1 score, then balanced accuracy, then accuracy. If CodeBERT or TF-IDF checkpoints are missing, those classifiers are skipped instead of breaking the comparison.

## Prepare CodeBERT Data

```bash
python -m lamps.main prepare-dataset --csv ./dataset/D2-6000snippets.csv --out ./data/train.jsonl
```

For the actual project dataset, the preferred workflow is:

```bash
python -m lamps.main prepare-codebert-splits --csv ./dataset/D2-6000snippets.csv --out-dir ./CodeBERT_Classifier/data --code-column "Setup.py"
```

Expected JSONL format:

```json
{"idx": "0", "func": "python source code here", "target": 0}
{"idx": "1", "func": "python source code here", "target": 1}
```

## Train CodeBERT Baseline

CodeBERT is the baseline from the paper. Train it only if your machine has enough resources and you need to reproduce the baseline experiment. For normal demo scans, TF-IDF or heuristic mode is lighter.

```bash
python -m lamps.main train-codebert --train ./CodeBERT_Classifier/data/train.jsonl --val ./CodeBERT_Classifier/data/val.jsonl --test ./CodeBERT_Classifier/data/test.jsonl --output-dir ./CodeBERT_Classifier/checkpoint
```

Defaults follow the paper/repo: `microsoft/codebert-base`, `block_size=400`, train batch `16`, eval batch `64`, learning rate `2e-5`, `5` epochs, seed `123456`.

## MCP Server

Run the MCP server over stdio:

```bash
python -m lamps_mcp.server
```

Example MCP client config:

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

The server exposes tools for package/archive scans, CodeBERT split preparation, dataset evaluation, CodeBERT training, TF-IDF training, and report reading. Startup and heuristic scans do not require `LLM_API_KEY`.

## Safety

The pipeline performs static analysis only. It downloads and extracts archives, but never installs, imports, or executes PyPI package code.
