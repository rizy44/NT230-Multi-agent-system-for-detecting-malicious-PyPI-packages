from __future__ import annotations

import csv
import json
import random
from pathlib import Path


def csv_to_jsonl(
    csv_path: str | Path,
    output_path: str | Path,
    code_column: str = "Setup.py",
    label_column: str | None = None,
    idx_column: str | None = None,
) -> None:
    with Path(csv_path).open(newline="", encoding="utf-8", errors="ignore") as src, Path(output_path).open(
        "w", encoding="utf-8"
    ) as dst:
        reader = csv.DictReader(src)
        fieldnames = reader.fieldnames or []
        resolved_label_column = label_column or _first_existing(fieldnames, ["target", "Label", "label", "Target"])
        if not resolved_label_column:
            raise ValueError(f"Could not find a label column in CSV. Available columns: {fieldnames}")
        if code_column not in fieldnames:
            raise ValueError(f"Could not find code column '{code_column}'. Available columns: {fieldnames}")
        for index, row in enumerate(reader):
            label_raw = row.get(resolved_label_column, "0")
            target = int(str(label_raw).strip().lower() in {"1", "malicious", "true"})
            payload = {
                "idx": row.get(idx_column, str(index)) if idx_column else str(index),
                "func": row.get(code_column, ""),
                "target": target,
            }
            dst.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _first_existing(fieldnames: list[str], candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate in fieldnames:
            return candidate
    return None


def create_codebert_splits(
    csv_path: str | Path,
    output_dir: str | Path,
    code_column: str = "Setup.py",
    label_column: str | None = None,
    idx_column: str | None = None,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 123456,
) -> dict[str, int]:
    if round(train_ratio + val_ratio + test_ratio, 6) != 1.0:
        raise ValueError("train_ratio + val_ratio + test_ratio must equal 1.0")

    rows = _read_codebert_rows(csv_path, code_column, label_column, idx_column)
    grouped = {0: [], 1: []}
    for row in rows:
        grouped[row["target"]].append(row)

    rng = random.Random(seed)
    for label_rows in grouped.values():
        rng.shuffle(label_rows)

    ordered_rows = _interleave_label_groups(grouped)
    n_total = len(ordered_rows)
    n_train = int(n_total * train_ratio)
    n_val = int(n_total * val_ratio)
    splits = {
        "train": ordered_rows[:n_train],
        "val": ordered_rows[n_train : n_train + n_val],
        "test": ordered_rows[n_train + n_val :],
    }

    for split_rows in splits.values():
        rng.shuffle(split_rows)

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    for split, split_rows in splits.items():
        _write_jsonl(destination / f"{split}.jsonl", split_rows)

    return {
        "total": len(rows),
        "train": len(splits["train"]),
        "val": len(splits["val"]),
        "test": len(splits["test"]),
        "benign": len(grouped[0]),
        "malicious": len(grouped[1]),
    }


def _read_codebert_rows(
    csv_path: str | Path,
    code_column: str,
    label_column: str | None,
    idx_column: str | None,
) -> list[dict]:
    with Path(csv_path).open(newline="", encoding="utf-8", errors="ignore") as src:
        reader = csv.DictReader(src)
        fieldnames = reader.fieldnames or []
        resolved_label_column = label_column or _first_existing(fieldnames, ["target", "Label", "label", "Target"])
        if not resolved_label_column:
            raise ValueError(f"Could not find a label column in CSV. Available columns: {fieldnames}")
        if code_column not in fieldnames:
            raise ValueError(f"Could not find code column '{code_column}'. Available columns: {fieldnames}")

        rows = []
        for index, row in enumerate(reader):
            label_raw = row.get(resolved_label_column, "0")
            rows.append(
                {
                    "idx": row.get(idx_column, str(index)) if idx_column else str(index),
                    "func": row.get(code_column, ""),
                    "target": int(str(label_raw).strip().lower() in {"1", "malicious", "true"}),
                }
            )
        return rows


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _interleave_label_groups(grouped: dict[int, list[dict]]) -> list[dict]:
    ordered_rows: list[dict] = []
    label_order = sorted(grouped)
    offsets = {label: 0 for label in label_order}
    remaining = sum(len(rows) for rows in grouped.values())
    while remaining:
        for label in label_order:
            offset = offsets[label]
            if offset >= len(grouped[label]):
                continue
            ordered_rows.append(grouped[label][offset])
            offsets[label] += 1
            remaining -= 1
    return ordered_rows
