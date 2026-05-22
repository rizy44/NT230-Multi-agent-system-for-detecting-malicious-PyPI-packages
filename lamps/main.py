from __future__ import annotations

import argparse
import json
from pathlib import Path

from lamps.core.codebert import ClassifierFactory, HeuristicClassifier
from lamps.core.config import Settings
from lamps.core.pipeline import LAMPSPipeline
from lamps.evaluation.metrics import classification_metrics
from lamps.evaluation.prepare_dataset import create_codebert_splits, csv_to_jsonl
from lamps.evaluation.train_tfidf import TfidfTrainingConfig, train_tfidf


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LAMPS-style PyPI malware detector")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a PyPI package or local archive")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--package", help="PyPI package name")
    source.add_argument("--archive", help="Local .tar.gz, .zip, or .whl archive")
    scan.add_argument("--classifier", choices=["auto", "best", "codebert", "tfidf", "heuristic"], default="auto")
    scan.add_argument("--package-name", default="local-archive", help="Name used for local archive reports")

    evaluate = subparsers.add_parser("evaluate", help="Evaluate a classifier on a CSV dataset")
    evaluate.add_argument("--dataset", required=True)
    evaluate.add_argument("--code-column", default="Setup.py")
    evaluate.add_argument("--label-column", default=None)
    evaluate.add_argument("--max-samples", type=int, default=0)
    evaluate.add_argument(
        "--classifier",
        choices=["heuristic", "tfidf", "codebert", "auto", "best"],
        default="heuristic",
        help="Classifier used for evaluation. Defaults to heuristic for backwards compatibility.",
    )

    compare = subparsers.add_parser("compare-classifiers", help="Evaluate classifiers and select the best by F1")
    compare.add_argument("--dataset", required=True)
    compare.add_argument("--code-column", default="Setup.py")
    compare.add_argument("--label-column", default=None)
    compare.add_argument("--max-samples", type=int, default=0)
    compare.add_argument(
        "--classifiers",
        nargs="+",
        choices=["heuristic", "tfidf", "codebert"],
        default=["heuristic", "tfidf", "codebert"],
        help="Classifier modes to compare. Unavailable model-backed classifiers are skipped.",
    )

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

    train_tfidf_parser = subparsers.add_parser(
        "train-tfidf",
        help="Train a fast TF-IDF + Logistic Regression malware classifier baseline",
    )
    train_tfidf_parser.add_argument("--dataset", required=True)
    train_tfidf_parser.add_argument("--text-column", default="Setup.py")
    train_tfidf_parser.add_argument("--label-column", default=None)
    train_tfidf_parser.add_argument("--validation-dataset", default=None)
    train_tfidf_parser.add_argument("--output-path", default=None)
    train_tfidf_parser.add_argument("--max-features", type=int, default=50000)

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
        metrics = _evaluate_csv(args, settings)
        print(json.dumps({"classifier": args.classifier, **metrics}, indent=2))
        return 0

    if args.command == "compare-classifiers":
        print(json.dumps(_compare_classifiers(args, settings), indent=2))
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

    if args.command == "train-tfidf":
        return _run_tfidf_training(args, settings)

    return 1


def _evaluate_csv(args, settings: Settings | None = None) -> dict:
    import csv

    classifier_mode = getattr(args, "classifier", "heuristic")
    if classifier_mode == "heuristic":
        classifier = HeuristicClassifier()
    else:
        if settings is None:
            settings = Settings.from_env()
        classifier = ClassifierFactory(settings.codebert_model_path, settings.tfidf_model_path).create(classifier_mode)
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


def _compare_classifiers(args, settings: Settings) -> dict:
    results: dict[str, dict] = {}
    skipped: dict[str, str] = {}
    for classifier in args.classifiers:
        try:
            metrics = _evaluate_csv(
                argparse.Namespace(
                    dataset=args.dataset,
                    code_column=args.code_column,
                    label_column=args.label_column,
                    max_samples=args.max_samples,
                    classifier=classifier,
                ),
                settings,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            skipped[classifier] = str(exc)
            continue
        results[classifier] = metrics

    if not results:
        raise RuntimeError(f"No classifiers could be evaluated. Skipped: {skipped}")

    best_classifier = max(
        results,
        key=lambda name: (
            results[name].get("f1", 0.0),
            results[name].get("balanced_accuracy", 0.0),
            results[name].get("accuracy", 0.0),
        ),
    )
    return {
        "best_classifier": best_classifier,
        "selection_metric": "f1",
        "results": results,
        "skipped": skipped,
    }


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


def _run_tfidf_training(args, settings: Settings) -> int:
    output_path = Path(args.output_path) if args.output_path else settings.tfidf_model_path
    metrics = train_tfidf(
        TfidfTrainingConfig(
            train_path=Path(args.dataset),
            output_path=output_path,
            text_column=args.text_column,
            label_column=args.label_column,
            validation_path=Path(args.validation_dataset) if args.validation_dataset else None,
            max_features=args.max_features,
        )
    )
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
