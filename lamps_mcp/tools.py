from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from lamps.core.config import Settings
from lamps.core.pipeline import LAMPSPipeline, _safe_name
from lamps.evaluation.prepare_dataset import create_codebert_splits
from lamps.evaluation.train_codebert import CodeBERTTrainingConfig, train_codebert
from lamps.evaluation.train_tfidf import TfidfTrainingConfig, train_tfidf
from lamps.main import _evaluate_csv

from lamps_mcp.schemas import (
    EvaluateDatasetArgs,
    PrepareCodeBERTSplitsArgs,
    ScanArchiveArgs,
    ScanPackageArgs,
    TrainCodeBERTArgs,
    TrainTfidfArgs,
)


def summarize_report(report, report_path: str | Path) -> dict[str, Any]:
    return {
        "package": report.package,
        "version": report.version,
        "verdict": report.verdict,
        "malicious_files": report.malicious_files,
        "files_analyzed": report.files_analyzed,
        "rationale": report.rationale,
        "report_path": str(report_path),
    }


def scan_package_tool(package: str, classifier: str = "auto") -> dict[str, Any]:
    args = ScanPackageArgs(package=package, classifier=classifier)
    settings = Settings.from_env()
    report = LAMPSPipeline(settings, classifier_mode=args.classifier).scan_package(args.package)
    report_path = settings.report_dir / f"{_safe_name(report.package)}-report.json"
    return summarize_report(report, report_path)


def scan_archive_tool(
    archive_path: str,
    package_name: str = "local-archive",
    classifier: str = "auto",
) -> dict[str, Any]:
    args = ScanArchiveArgs(archive_path=archive_path, package_name=package_name, classifier=classifier)
    settings = Settings.from_env()
    report = LAMPSPipeline(settings, classifier_mode=args.classifier).scan_archive(
        args.archive_path,
        package=args.package_name,
    )
    report_path = settings.report_dir / f"{_safe_name(report.package)}-report.json"
    return summarize_report(report, report_path)


def prepare_codebert_splits_tool(
    csv_path: str = "dataset/D2-6000snippets.csv",
    output_dir: str = "CodeBERT_Classifier/data",
    code_column: str = "Setup.py",
    label_column: str | None = None,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 123456,
) -> dict[str, int]:
    args = PrepareCodeBERTSplitsArgs(
        csv_path=csv_path,
        output_dir=output_dir,
        code_column=code_column,
        label_column=label_column,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        seed=seed,
    )
    return create_codebert_splits(
        csv_path=args.csv_path,
        output_dir=args.output_dir,
        code_column=args.code_column,
        label_column=args.label_column,
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        test_ratio=args.test_ratio,
        seed=args.seed,
    )


def evaluate_dataset_tool(
    dataset_path: str = "dataset/D2-6000snippets.csv",
    code_column: str = "Setup.py",
    label_column: str | None = None,
    max_samples: int = 50,
    classifier: str = "heuristic",
) -> dict[str, Any]:
    args = EvaluateDatasetArgs(
        dataset_path=dataset_path,
        code_column=code_column,
        label_column=label_column,
        max_samples=max_samples,
        classifier=classifier,
    )
    settings = Settings.from_env()
    return _evaluate_csv(
        SimpleNamespace(
            dataset=args.dataset_path,
            code_column=args.code_column,
            label_column=args.label_column,
            max_samples=args.max_samples,
            classifier=args.classifier,
        ),
        settings,
    )


def train_codebert_tool(
    train_path: str = "CodeBERT_Classifier/data/train.jsonl",
    val_path: str = "CodeBERT_Classifier/data/val.jsonl",
    test_path: str = "CodeBERT_Classifier/data/test.jsonl",
    output_dir: str = "CodeBERT_Classifier/checkpoint",
) -> dict[str, Any]:
    args = TrainCodeBERTArgs(
        train_path=train_path,
        val_path=val_path,
        test_path=test_path,
        output_dir=output_dir,
    )


def train_tfidf_tool(
    dataset_path: str = "dataset/D2-6000snippets.csv",
    text_column: str = "Setup.py",
    label_column: str | None = None,
    validation_dataset: str | None = None,
    output_path: str = "models/tfidf-malware-detector/model.joblib",
    max_features: int = 50000,
) -> dict[str, Any]:
    args = TrainTfidfArgs(
        dataset_path=dataset_path,
        text_column=text_column,
        label_column=label_column,
        validation_dataset=validation_dataset,
        output_path=output_path,
        max_features=max_features,
    )
    return train_tfidf(
        TfidfTrainingConfig(
            train_path=Path(args.dataset_path),
            output_path=Path(args.output_path),
            text_column=args.text_column,
            label_column=args.label_column,
            validation_path=Path(args.validation_dataset) if args.validation_dataset else None,
            max_features=args.max_features,
        )
    )
    return train_codebert(
        CodeBERTTrainingConfig(
            train_path=Path(args.train_path),
            val_path=Path(args.val_path),
            test_path=Path(args.test_path),
            output_dir=Path(args.output_dir),
        )
    )


def list_reports_tool(report_dir: str = "reports") -> dict[str, list[dict[str, Any]]]:
    reports = []
    for path in sorted(Path(report_dir).glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        reports.append(
            {
                "path": str(path),
                "package": payload.get("package"),
                "verdict": payload.get("verdict"),
            }
        )
    return {"reports": reports}


def read_report_tool(report_path: str) -> dict[str, Any]:
    with Path(report_path).open(encoding="utf-8") as handle:
        return json.load(handle)
