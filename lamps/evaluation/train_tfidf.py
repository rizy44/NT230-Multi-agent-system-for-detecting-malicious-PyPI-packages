from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

from lamps.evaluation.metrics import classification_metrics


@dataclass(slots=True)
class TfidfTrainingConfig:
    train_path: Path
    output_path: Path
    text_column: str = "Setup.py"
    label_column: str | None = None
    validation_path: Path | None = None
    max_features: int = 50000


def train_tfidf(config: TfidfTrainingConfig) -> dict:
    try:
        import joblib
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
    except Exception as exc:
        raise RuntimeError("TF-IDF training requires scikit-learn and joblib.") from exc

    train_texts, train_labels = _read_labeled_csv(
        config.train_path,
        config.text_column,
        config.label_column,
    )
    model = Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    lowercase=False,
                    max_features=config.max_features,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=123456,
                ),
            ),
        ]
    )
    model.fit(train_texts, train_labels)

    metrics: dict[str, float | int | dict] = {"train_samples": len(train_labels)}
    if config.validation_path:
        validation_texts, validation_labels = _read_labeled_csv(
            config.validation_path,
            config.text_column,
            config.label_column,
        )
        predictions = [int(value) for value in model.predict(validation_texts)]
        metrics.update(classification_metrics(validation_labels, predictions))
        metrics["validation_samples"] = len(validation_labels)

    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, config.output_path)
    metadata_path = config.output_path.with_suffix(".metrics.json")
    metadata_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def _read_labeled_csv(
    path: str | Path,
    text_column: str,
    label_column: str | None,
) -> tuple[list[str], list[int]]:
    with Path(path).open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        resolved_label_column = label_column or _first_existing(fieldnames, ["target", "Label", "label", "Target"])
        if not resolved_label_column:
            raise ValueError(f"Could not find a label column in CSV. Available columns: {fieldnames}")
        if text_column not in fieldnames:
            raise ValueError(f"Could not find text column '{text_column}'. Available columns: {fieldnames}")

        texts: list[str] = []
        labels: list[int] = []
        for row in reader:
            texts.append(row.get(text_column, ""))
            labels.append(_normalize_label(row.get(resolved_label_column, "0")))
        if not texts:
            raise ValueError(f"No training rows found in {path}.")
        return texts, labels


def _first_existing(fieldnames: list[str], candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate in fieldnames:
            return candidate
    return None


def _normalize_label(value: object) -> int:
    return int(str(value).strip().lower() in {"1", "malicious", "true"})
