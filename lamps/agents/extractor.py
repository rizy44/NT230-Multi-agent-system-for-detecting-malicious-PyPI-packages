from __future__ import annotations

from pathlib import Path

from lamps.core.archive import extract_archive_safely
from lamps.core.schemas import ExtractionResult


class ExtractorAgent:
    role = "Code File Extractor"

    def extract(self, archive_path: str | Path, extract_dir: str | Path) -> ExtractionResult:
        return extract_archive_safely(archive_path, extract_dir)
