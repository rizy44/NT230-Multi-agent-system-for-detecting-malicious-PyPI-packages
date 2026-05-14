from __future__ import annotations

from lamps.core.llm_client import LLMClient
from lamps.core.schemas import FileClassification, ScanReport


class VerdictAgent:
    role = "Package Verdict Synthesizer"

    def __init__(self, llm_client: LLMClient | None = None):
        self.llm_client = llm_client

    def decide(
        self,
        package: str,
        version: str | None,
        results: list[FileClassification],
        agent_trace: dict | None = None,
    ) -> ScanReport:
        malicious = [result for result in results if result.label == "malicious"]
        verdict = "malicious" if malicious else "benign"
        malicious_files = [result.path for result in malicious]
        rationale = self._build_rationale(package, verdict, malicious, len(results))
        return ScanReport(
            package=package,
            version=version,
            verdict=verdict,
            malicious_files=malicious_files,
            files_analyzed=len(results),
            file_results=results,
            rationale=rationale,
            agent_trace=agent_trace or {"fetcher": {}, "extractor": {}, "classifier": {}, "verdict": {}},
        )

    def _build_rationale(
        self,
        package: str,
        verdict: str,
        malicious: list[FileClassification],
        files_analyzed: int,
    ) -> str:
        default = _deterministic_rationale(verdict, malicious, files_analyzed)
        if not self.llm_client or not self.llm_client.available:
            return default
        summary = "\n".join(
            f"{item.path}: {item.label} score={item.score:.2f} signals={','.join(item.signals)}"
            for item in malicious[:10]
        ) or "No malicious files."
        prompt = (
            f"Package: {package}\n"
            f"Policy verdict: {verdict}\n"
            f"Analyzed files: {files_analyzed}\n"
            f"Malicious file summary:\n{summary}\n\n"
            "Explain the verdict concisely. Do not change the policy verdict."
        )
        return self.llm_client.complete_or_default(
            "You are the Verdict Agent in LAMPS. Explain static file-level malware findings.",
            prompt,
            default,
        )


def _deterministic_rationale(
    verdict: str,
    malicious: list[FileClassification],
    files_analyzed: int,
) -> str:
    if verdict == "benign":
        return "All analyzed Python files were classified as benign."
    details = []
    for item in malicious:
        signals = f" signals: {', '.join(item.signals)}" if item.signals else ""
        details.append(f"{item.path} was classified as malicious ({item.score:.2f}).{signals}")
    return f"{len(malicious)} of {files_analyzed} files were flagged. " + " ".join(details)
