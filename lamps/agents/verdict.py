from __future__ import annotations

from lamps.core.llm_client import LLMClient
from lamps.core.schemas import FileClassification, ScanReport


class VerdictAgent:
    role = "Package Verdict Synthesizer"

    def __init__(self, llm_client: LLMClient | None = None):
        self.llm_client = llm_client
        self.last_reasoning: dict[str, object] = {
            "llm_assisted": bool(llm_client and llm_client.available),
            "policy": "package is malicious if any analyzed Python file is malicious",
        }

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
        self.last_reasoning = {
            "llm_assisted": bool(self.llm_client and self.llm_client.available),
            "policy": "package is malicious if any analyzed Python file is malicious",
            "malicious_file_count": len(malicious),
            "rationale_source": "llm" if self.llm_client and self.llm_client.available else "deterministic",
        }
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
            "Return exactly this English structure:\n"
            "Issue: <specific suspicious behavior or model finding; mention subprocess, PowerShell, encoded command, download/execute only if present in signals or summary>.\n"
            "Location: <file path, classifier confidence, and signals if available>.\n"
            "Install impact: <what could happen when setup.py/install-time code runs; be concrete but do not invent URLs or payloads>.\n"
            "Keep it to 3 lines. Do not change the policy verdict."
        )
        return self.llm_client.complete_or_default(
            "You are the Verdict Agent in LAMPS. Produce concise, evidence-based English security findings.",
            prompt,
            default,
            max_tokens=190,
        )


def _deterministic_rationale(
    verdict: str,
    malicious: list[FileClassification],
    files_analyzed: int,
) -> str:
    if verdict == "benign":
        return (
            "Issue: No malicious behavior was detected in the analyzed Python files.\n"
            f"Location: {files_analyzed} Python file(s) were classified as benign.\n"
            "Install impact: Static analysis found no evidence of dangerous install-time or import-time behavior."
        )
    top = malicious[0]
    signals = ", ".join(top.signals) if top.signals else "model confidence"
    return (
        "Issue: A Python file was classified as malicious based on static signals or model confidence.\n"
        f"Location: {top.path} score={top.score:.2f} signals={signals}.\n"
        "Install impact: The package may execute unsafe code during installation or import, potentially compromising the host environment."
    )
