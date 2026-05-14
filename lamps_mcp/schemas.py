from __future__ import annotations

from dataclasses import dataclass


VALID_CLASSIFIERS = {"auto", "codebert", "heuristic"}


def validate_classifier(classifier: str) -> str:
    if classifier not in VALID_CLASSIFIERS:
        raise ValueError(f"classifier must be one of {sorted(VALID_CLASSIFIERS)}")
    return classifier


@dataclass(slots=True)
class ScanPackageArgs:
    package: str
    classifier: str = "auto"

    def __post_init__(self) -> None:
        self.classifier = validate_classifier(self.classifier)


@dataclass(slots=True)
class ScanArchiveArgs:
    archive_path: str
    package_name: str = "local-archive"
    classifier: str = "auto"

    def __post_init__(self) -> None:
        self.classifier = validate_classifier(self.classifier)


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

