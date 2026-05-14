from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any


Label = str


@dataclass(slots=True)
class PackageSource:
    package: str
    version: str | None
    url: str | None
    archive_path: str | None
    source_type: str


@dataclass(slots=True)
class ExtractionResult:
    archive_path: str
    extract_dir: str
    python_files: list[Any]
    skipped_files: list[str] = field(default_factory=list)
    note: str = ""


@dataclass(slots=True)
class FileClassification:
    path: str
    label: Label
    score: float
    signals: list[str] = field(default_factory=list)
    classifier_mode: str = "unknown"

    def __post_init__(self) -> None:
        normalized = self.label.lower().strip()
        if normalized not in {"benign", "malicious"}:
            raise ValueError(f"Unsupported label: {self.label}")
        self.label = normalized
        self.score = float(max(0.0, min(1.0, self.score)))


@dataclass(slots=True)
class ScanReport:
    package: str
    version: str | None
    verdict: Label
    malicious_files: list[str]
    files_analyzed: int
    file_results: list[FileClassification]
    rationale: str
    agent_trace: dict[str, Any]

    def __post_init__(self) -> None:
        normalized = self.verdict.lower().strip()
        if normalized not in {"benign", "malicious"}:
            raise ValueError(f"Unsupported verdict: {self.verdict}")
        self.verdict = normalized

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
