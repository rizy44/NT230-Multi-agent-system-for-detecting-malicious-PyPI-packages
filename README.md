# LAMPS

This workspace contains a practical replica of the LAMPS pipeline from the JSS paper and the author's `lamps-jss` repository. It keeps the four-agent structure while replacing local LLaMA 3 with an optional LLM API.

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

`--classifier auto` uses a valid local CodeBERT checkpoint when available. If the checkpoint is missing or incomplete, it falls back to the transparent heuristic classifier so the demo can run on modest hardware.

## Evaluate

```bash
python -m lamps.main evaluate --dataset ./dataset/D2-6000snippets.csv --code-column "Setup.py" --max-samples 50
```

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

## Train CodeBERT

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

The server exposes tools for package/archive scans, CodeBERT split preparation, heuristic dataset evaluation, CodeBERT training, and report reading. Startup and heuristic scans do not require `LLM_API_KEY`.

## Safety

The pipeline performs static analysis only. It downloads and extracts archives, but never installs, imports, or executes PyPI package code.
