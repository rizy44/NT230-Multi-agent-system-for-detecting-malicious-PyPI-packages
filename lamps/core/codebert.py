from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from lamps.core.schemas import FileClassification


SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    ("base64", r"\bbase64\b|b64decode"),
    ("subprocess", r"\bsubprocess\b|Popen\(|check_output\(|check_call\("),
    ("os-system", r"\bos\.system\(|os\.popen\("),
    ("eval-exec", r"\beval\(|\bexec\("),
    ("network", r"\brequests\.|urllib\.request|socket\.|http://|https://"),
    ("powershell", r"powershell|FromBase64String|EncodedCommand"),
    ("download-execute", r"curl\s+|wget\s+|Invoke-WebRequest|urlopen\("),
    ("file-manipulation", r"shutil\.rmtree|os\.remove|os\.unlink"),
]


class HeuristicClassifier:
    mode = "heuristic"

    def classify_code(self, code: str, path: str) -> FileClassification:
        signals = [
            name for name, pattern in SUSPICIOUS_PATTERNS if re.search(pattern, code, flags=re.IGNORECASE)
        ]
        risky_combo = {"base64", "subprocess"} <= set(signals) or {"powershell", "download-execute"} & set(signals)
        if risky_combo:
            score = 0.9
        elif len(signals) >= 2:
            score = 0.78
        elif signals:
            score = 0.62
        else:
            score = 0.96
        label = "malicious" if signals and score >= 0.75 else "benign"
        return FileClassification(path=path, label=label, score=score, signals=signals, classifier_mode=self.mode)


class CodeBERTClassifier:
    mode = "codebert"

    def __init__(self, model_path: str | Path, block_size: int = 400):
        self.model_path = Path(model_path)
        self.block_size = block_size
        self._pipeline = None
        self._load_error: Exception | None = None

    @property
    def available(self) -> bool:
        if not self.model_path.exists():
            return False
        expected_model_files = {
            "config.json",
            "pytorch_model.bin",
            "model.safetensors",
            "tf_model.h5",
        }
        has_config = (self.model_path / "config.json").exists()
        has_weights = any((self.model_path / name).exists() for name in expected_model_files - {"config.json"})
        has_tokenizer = any(
            (self.model_path / name).exists()
            for name in ("tokenizer.json", "vocab.json", "vocab.txt", "merges.txt")
        )
        return has_config and has_weights and has_tokenizer

    def _load(self):
        if self._pipeline is not None:
            return self._pipeline
        if not self.available:
            raise FileNotFoundError(f"CodeBERT checkpoint is not valid or complete: {self.model_path}")
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
        except Exception as exc:
            self._load_error = exc
            raise RuntimeError("transformers is required for CodeBERT mode.") from exc
        model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
        tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        self._pipeline = pipeline("text-classification", model=model, tokenizer=tokenizer)
        return self._pipeline

    def classify_code(self, code: str, path: str) -> FileClassification:
        pipe = self._load()
        prompt = (
            "You are a security expert. Classify the following Python code as either malicious or benign.\n\n"
            "Malicious code may include obfuscation, data exfiltration, network exploitation, or hidden behavior.\n\n"
            f"Code:\n{code[: self.block_size * 4]}"
        )
        raw = pipe(prompt)[0]
        label = _normalize_model_label(str(raw["label"]))
        return FileClassification(
            path=path,
            label=label,
            score=float(raw["score"]),
            signals=[],
            classifier_mode=self.mode,
        )


class TfidfClassifier:
    mode = "tfidf"

    def __init__(self, model_path: str | Path):
        self.model_path = Path(model_path)
        self._model: Any | None = None

    @property
    def available(self) -> bool:
        return self.model_path.exists()

    def _load(self):
        if self._model is not None:
            return self._model
        if not self.available:
            raise FileNotFoundError(f"TF-IDF checkpoint is not valid or complete: {self.model_path}")
        try:
            import joblib
        except Exception as exc:
            raise RuntimeError("joblib is required for TF-IDF mode.") from exc
        self._model = joblib.load(self.model_path)
        return self._model

    def classify_code(self, code: str, path: str) -> FileClassification:
        model = self._load()
        prediction = int(model.predict([code])[0])
        if hasattr(model, "predict_proba"):
            probability = float(model.predict_proba([code])[0][prediction])
        else:
            probability = 1.0
        label = "malicious" if prediction == 1 else "benign"
        return FileClassification(
            path=path,
            label=label,
            score=probability,
            signals=[],
            classifier_mode=self.mode,
        )


def _normalize_model_label(label: str) -> str:
    cleaned = label.lower().strip()
    if cleaned in {"malicious", "label_1", "1", "true"}:
        return "malicious"
    return "benign"


class ClassifierFactory:
    def __init__(self, codebert_model_path: str | Path, tfidf_model_path: str | Path | None = None):
        self.codebert_model_path = Path(codebert_model_path)
        self.tfidf_model_path = Path(tfidf_model_path) if tfidf_model_path else None

    def create(self, mode: str):
        if mode == "heuristic":
            return HeuristicClassifier()
        if mode == "tfidf":
            if not self.tfidf_model_path:
                raise FileNotFoundError("TF-IDF model path is not configured.")
            return TfidfClassifier(self.tfidf_model_path)
        if mode == "codebert":
            return CodeBERTClassifier(self.codebert_model_path)
        if mode in {"auto", "best"}:
            if self.tfidf_model_path and TfidfClassifier(self.tfidf_model_path).available:
                return TfidfClassifier(self.tfidf_model_path)
            if CodeBERTClassifier(self.codebert_model_path).available:
                return CodeBERTClassifier(self.codebert_model_path)
            return HeuristicClassifier()
        raise ValueError(f"Unsupported classifier mode: {mode}")
