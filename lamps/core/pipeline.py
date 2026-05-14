from __future__ import annotations

from pathlib import Path
from typing import Any

from lamps.agents.classifier import ClassifierAgent
from lamps.agents.extractor import ExtractorAgent
from lamps.agents.fetcher import FetcherAgent
from lamps.agents.verdict import VerdictAgent
from lamps.core.codebert import ClassifierFactory
from lamps.core.config import Settings
from lamps.core.llm_client import LLMClient
from lamps.core.schemas import ScanReport


class LAMPSPipeline:
    def __init__(self, settings: Settings, classifier_mode: str = "auto"):
        self.settings = settings
        self.llm_client = LLMClient(settings.llm_api_key, settings.llm_api_base, settings.llm_model)
        self.fetcher = FetcherAgent(llm_client=self.llm_client)
        self.extractor = ExtractorAgent()
        classifier = ClassifierFactory(settings.codebert_model_path).create(classifier_mode)
        self.classifier = ClassifierAgent(classifier)
        self.verdict = VerdictAgent(self.llm_client)
        self.classifier_mode = getattr(classifier, "mode", classifier_mode)

    def scan_package(self, package: str) -> ScanReport:
        source = self.fetcher.fetch(package, self.settings.download_dir)
        return self._scan_source(source)

    def scan_archive(self, archive: str | Path, package: str = "local-archive") -> ScanReport:
        source = self.fetcher.from_archive(archive, package=package)
        return self._scan_source(source)

    def _scan_source(self, source) -> ScanReport:
        extract_target = self.settings.extract_dir / _safe_name(source.package)
        extraction = self.extractor.extract(source.archive_path, extract_target)
        classifications = self.classifier.classify_files(Path(extraction.extract_dir), extraction.python_files)
        trace: dict[str, Any] = {
            "fetcher": {
                "package": source.package,
                "version": source.version,
                "url": source.url,
                "source_type": source.source_type,
                "archive_path": source.archive_path,
            },
            "extractor": {
                "extract_dir": extraction.extract_dir,
                "python_files": [p.as_posix() for p in extraction.python_files],
                "skipped_files": extraction.skipped_files,
            },
            "classifier": {
                "mode": self.classifier_mode,
                "files_analyzed": len(classifications),
            },
            "verdict": {
                "policy": "package is malicious if any analyzed Python file is malicious",
            },
        }
        report = self.verdict.decide(source.package, source.version, classifications, trace)
        self._write_report(report)
        return report

    def _write_report(self, report: ScanReport) -> Path:
        self.settings.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.settings.report_dir / f"{_safe_name(report.package)}-report.json"
        path.write_text(report.to_json(), encoding="utf-8")
        return path


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value) or "package"
