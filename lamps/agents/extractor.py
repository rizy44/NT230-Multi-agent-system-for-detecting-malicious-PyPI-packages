from __future__ import annotations

from pathlib import Path

from lamps.core.archive import extract_archive_safely
from lamps.core.llm_client import LLMClient
from lamps.core.schemas import ExtractionResult


class ExtractorAgent:
    role = "Code File Extractor"

    def __init__(self, llm_client: LLMClient | None = None):
        self.llm_client = llm_client
        self.last_reasoning: dict[str, object] = {
            "llm_assisted": bool(llm_client and llm_client.available),
            "summary": "LLM is not configured; extraction used deterministic archive safety checks and Python file filtering.",
        }

    def extract(self, archive_path: str | Path, extract_dir: str | Path) -> ExtractionResult:
        result = extract_archive_safely(archive_path, extract_dir)
        selected = [path.as_posix() for path in result.python_files]
        skipped = result.skipped_files
        summary = self._llm_note(
            "You are the Extractor Agent in LAMPS. Return one short sentence, max 30 words. No bullets. Do not request execution.",
            (
                f"Archive: {archive_path}\n"
                f"Selected Python files ({len(selected)}): {selected[:30]}\n"
                f"Skipped Python files ({len(skipped)}): {skipped[:30]}"
            ),
            (
                f"Selected {len(selected)} Python source files for static analysis after safe extraction; "
                f"skipped {len(skipped)} noisy or non-target Python files."
            ),
        )
        self.last_reasoning = {
            "llm_assisted": bool(self.llm_client and self.llm_client.available),
            "summary": summary,
            "selected_python_files": len(selected),
            "skipped_python_files": len(skipped),
        }
        return result

    def _llm_note(self, system: str, user: str, default: str) -> str:
        if not self.llm_client or not self.llm_client.available:
            return default
        return self.llm_client.complete_or_default(system, user, default, max_tokens=70)
