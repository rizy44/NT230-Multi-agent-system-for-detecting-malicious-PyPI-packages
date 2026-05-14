from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(slots=True)
class CodeBERTTrainingConfig:
    train_path: Path
    val_path: Path
    test_path: Path
    output_dir: Path
    base_model: str = "microsoft/codebert-base"
    block_size: int = 400
    train_batch_size: int = 16
    eval_batch_size: int = 64
    learning_rate: float = 2e-5
    epochs: int = 5
    seed: int = 123456


def train_codebert(config: CodeBERTTrainingConfig) -> dict:
    try:
        import numpy as np
        import torch
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, balanced_accuracy_score
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
            set_seed,
        )
    except Exception as exc:
        raise RuntimeError("CodeBERT training requires torch, transformers, numpy, and scikit-learn.") from exc

    set_seed(config.seed)
    tokenizer = AutoTokenizer.from_pretrained(config.base_model)
    model = AutoModelForSequenceClassification.from_pretrained(config.base_model, num_labels=2)

    train_dataset = JsonlCodeDataset(config.train_path, tokenizer, config.block_size, torch)
    val_dataset = JsonlCodeDataset(config.val_path, tokenizer, config.block_size, torch)
    test_dataset = JsonlCodeDataset(config.test_path, tokenizer, config.block_size, torch)

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)
        return {
            "accuracy": accuracy_score(labels, predictions),
            "precision": precision_score(labels, predictions, zero_division=0),
            "recall": recall_score(labels, predictions, zero_division=0),
            "f1": f1_score(labels, predictions, zero_division=0),
            "balanced_accuracy": balanced_accuracy_score(labels, predictions),
        }

    training_kwargs = {
        "output_dir": str(config.output_dir),
        "num_train_epochs": config.epochs,
        "per_device_train_batch_size": config.train_batch_size,
        "per_device_eval_batch_size": config.eval_batch_size,
        "learning_rate": config.learning_rate,
        "seed": config.seed,
        "save_strategy": "epoch",
        "load_best_model_at_end": True,
        "metric_for_best_model": "f1",
        "report_to": [],
    }
    try:
        training_args = TrainingArguments(eval_strategy="epoch", **training_kwargs)
    except TypeError:
        training_args = TrainingArguments(evaluation_strategy="epoch", **training_kwargs)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )
    trainer.train()
    metrics = trainer.evaluate(test_dataset)
    trainer.save_model(str(config.output_dir))
    tokenizer.save_pretrained(str(config.output_dir))
    return {key: float(value) for key, value in metrics.items() if isinstance(value, (int, float))}


class JsonlCodeDataset:
    def __init__(self, path: Path, tokenizer, block_size: int, torch_module):
        self.examples = []
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                item = json.loads(line)
                encoded = tokenizer(
                    str(item["func"]),
                    truncation=True,
                    padding="max_length",
                    max_length=block_size,
                    return_tensors="pt",
                )
                self.examples.append(
                    {
                        "input_ids": encoded["input_ids"].squeeze(0),
                        "attention_mask": encoded["attention_mask"].squeeze(0),
                        "labels": torch_module.tensor(int(item["target"])),
                    }
                )

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, index: int):
        return self.examples[index]
