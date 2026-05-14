from __future__ import annotations


def classification_metrics(y_true: list[int], y_pred: list[int]) -> dict:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length.")
    if not y_true:
        raise ValueError("At least one sample is required.")

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    accuracy = (tp + tn) / len(y_true)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    specificity = _safe_div(tn, tn + fp)
    balanced_accuracy = (recall + specificity) / 2
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "balanced_accuracy": balanced_accuracy,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
    }


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0
