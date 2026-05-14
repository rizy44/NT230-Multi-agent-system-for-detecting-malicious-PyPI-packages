from __future__ import annotations

import argparse
import json
from pathlib import Path

from lamps.core.codebert import HeuristicClassifier
from lamps.core.config import Settings
from lamps.core.pipeline import LAMPSPipeline
from lamps.evaluation.metrics import classification_metrics
from lamps.evaluation.prepare_dataset import create_codebert_splits, csv_to_jsonl


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LAMPS-style PyPI malware detector")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a PyPI package or local archive")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--package", help="PyPI package name")
    source.add_argument("--archive", help="Local .tar.gz, .zip, or .whl archive")
    scan.add_argument("--classifier", choices=["auto", "codebert", "heuristic"], default="auto")
    scan.add_argument("--package-name", default="local-archive", help="Name used for local archive reports")

    evaluate = subparsers.add_parser("evaluate", help="Evaluate the heuristic classifier on a CSV dataset")
    evaluate.add_argument("--dataset", required=True)
    evaluate.add_argument("--code-column", default="Setup.py")
    evaluate.add_argument("--label-column", default=None)
    evaluate.add_argument("--max-samples", type=int, default=0)

    prepare = subparsers.add_parser("prepare-dataset", help="Convert CSV dataset to CodeBERT JSONL")
    prepare.add_argument("--csv", required=True)
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--code-column", default="Setup.py")
    prepare.add_argument("--label-column", default=None)

    split = subparsers.add_parser("prepare-codebert-splits", help="Create train/val/test JSONL files for CodeBERT")
    split.add_argument("--csv", default="dataset/D2-6000snippets.csv")
    split.add_argument("--out-dir", default="CodeBERT_Classifier/data")
    split.add_argument("--code-column", default="Setup.py")
    split.add_argument("--label-column", default=None)
    split.add_argument("--train-ratio", type=float, default=0.8)
    split.add_argument("--val-ratio", type=float, default=0.1)
    split.add_argument("--test-ratio", type=float, default=0.1)
    split.add_argument("--seed", type=int, default=123456)

    train = subparsers.add_parser("train-codebert", help="Run the CodeBERT training script with LAMPS defaults")
    train.add_argument("--train", required=True)
    train.add_argument("--val", required=True)
    train.add_argument("--test", required=True)
    train.add_argument("--output-dir", default="models/codebert-malware-detector/saved_models/codebert-finetuned")

    args = parser.parse_args(argv)
    settings = Settings.from_env()

    if args.command == "scan":
        pipeline = LAMPSPipeline(settings, classifier_mode=args.classifier)
        if args.package:
            report = pipeline.scan_package(args.package)
        else:
            report = pipeline.scan_archive(args.archive, package=args.package_name)
        print(report.to_json())
        return 0

    if args.command == "evaluate":
        print(json.dumps(_evaluate_csv(args), indent=2))
        return 0

    if args.command == "prepare-dataset":
        csv_to_jsonl(args.csv, args.out, args.code_column, args.label_column)
        print(f"Wrote {args.out}")
        return 0

    if args.command == "prepare-codebert-splits":
        summary = create_codebert_splits(
            csv_path=args.csv,
            output_dir=args.out_dir,
            code_column=args.code_column,
            label_column=args.label_column,
            train_ratio=args.train_ratio,
            val_ratio=args.val_ratio,
            test_ratio=args.test_ratio,
            seed=args.seed,
        )
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "train-codebert":
        return _run_codebert_training(args)

    return 1


def _evaluate_csv(args) -> dict:
    import csv

    classifier = HeuristicClassifier()
    y_true: list[int] = []
    y_pred: list[int] = []
    with Path(args.dataset).open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        label_column = args.label_column or _first_existing(fieldnames, ["target", "Label", "label", "Target"])
        if not label_column:
            raise ValueError(f"Could not find a label column in CSV. Available columns: {fieldnames}")
        if args.code_column not in fieldnames:
            raise ValueError(f"Could not find code column '{args.code_column}'. Available columns: {fieldnames}")
        for index, row in enumerate(reader):
            if args.max_samples and index >= args.max_samples:
                break
            code = row.get(args.code_column, "")
            label = str(row.get(label_column, "0")).strip().lower()
            y_true.append(1 if label in {"1", "malicious", "true"} else 0)
            result = classifier.classify_code(code, f"row-{index}")
            y_pred.append(1 if result.label == "malicious" else 0)
    return classification_metrics(y_true, y_pred)


def _first_existing(fieldnames: list[str], candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate in fieldnames:
            return candidate
    return None


def _run_codebert_training(args) -> int:
    from lamps.evaluation.train_codebert import CodeBERTTrainingConfig, train_codebert

    metrics = train_codebert(
        CodeBERTTrainingConfig(
            train_path=Path(args.train),
            val_path=Path(args.val),
            test_path=Path(args.test),
            output_dir=Path(args.output_dir),
        )
    )
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
