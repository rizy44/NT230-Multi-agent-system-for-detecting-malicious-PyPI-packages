from __future__ import annotations

from pathlib import Path

from lamps.core.schemas import FileClassification


class ClassifierAgent:
    role = "Security Code Classifier"

    def __init__(self, classifier):
        self.classifier = classifier

    def classify_file(self, file_path: Path, display_path: str | None = None) -> FileClassification:
        code = file_path.read_text(encoding="utf-8", errors="ignore")
        return self.classifier.classify_code(code, display_path or file_path.as_posix())

    def classify_files(self, base_dir: Path, relative_paths: list[Path]) -> list[FileClassification]:
        results: list[FileClassification] = []
        for relative in relative_paths:
            results.append(self.classify_file(base_dir / relative, relative.as_posix()))
        return results
