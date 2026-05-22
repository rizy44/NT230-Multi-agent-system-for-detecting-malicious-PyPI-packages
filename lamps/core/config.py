from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


def load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv
    except Exception:
        return
    load_dotenv()


@dataclass(slots=True)
class Settings:
    llm_api_key: str | None
    llm_api_base: str
    llm_model: str
    codebert_model_path: Path
    tfidf_model_path: Path
    download_dir: Path
    extract_dir: Path
    report_dir: Path

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv_if_available()
        return cls(
            llm_api_key=os.getenv("LLM_API_KEY"),
            llm_api_base=os.getenv("LLM_API_BASE", "https://api.openai.com/v1"),
            llm_model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
            codebert_model_path=Path(os.getenv("CODEBERT_MODEL_PATH", "models/codebert-malware-detector")),
            tfidf_model_path=Path(os.getenv("TFIDF_MODEL_PATH", "models/tfidf-malware-detector/model.joblib")),
            download_dir=Path(os.getenv("DOWNLOAD_DIR", "downloads")),
            extract_dir=Path(os.getenv("EXTRACT_DIR", "extracted")),
            report_dir=Path(os.getenv("REPORT_DIR", "reports")),
        )
