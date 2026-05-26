from __future__ import annotations

from pathlib import Path

from lamps.core.llm_client import LLMClient
from lamps.core.pypi_client import PyPIClient
from lamps.core.schemas import PackageSource


class FetcherAgent:
    role = "Package Harvester"

    def __init__(self, pypi_client: PyPIClient | None = None, llm_client: LLMClient | None = None):
        self.pypi_client = pypi_client or PyPIClient()
        self.llm_client = llm_client
        self.last_reasoning: dict[str, str | bool] = {
            "llm_assisted": bool(llm_client and llm_client.available),
            "summary": "LLM is not configured; package retrieval used deterministic PyPI client logic.",
        }

    def normalize_package_name(self, package: str) -> str:
        cleaned = package.strip()
        if not self.llm_client or not self.llm_client.available:
            return cleaned
        return self.llm_client.complete_or_default(
            "You normalize PyPI package names. Return only the package name.",
            cleaned,
            cleaned,
        ).split()[0].strip("`'\"")

    def fetch(self, package: str, download_dir: str | Path) -> PackageSource:
        normalized = self.normalize_package_name(package)
        plan = self._llm_note(
            "You are the Fetcher Agent in LAMPS. Explain the safe retrieval plan in one concise sentence.",
            f"Requested package: {package}\nNormalized package: {normalized}\nDownload directory: {download_dir}",
            "Resolve package metadata through PyPI, prefer a source archive, download it locally, and never install or execute package code.",
        )
        artifact = self.pypi_client.choose_artifact(normalized)
        archive_path = self.pypi_client.download_artifact(artifact, download_dir)
        self.last_reasoning = {
            "llm_assisted": bool(self.llm_client and self.llm_client.available),
            "normalized_package": normalized,
            "retrieval_plan": plan,
            "selected_artifact": artifact.filename,
            "source_type": artifact.packagetype,
        }
        return PackageSource(
            package=artifact.package,
            version=artifact.version,
            url=artifact.url,
            archive_path=str(archive_path),
            source_type=artifact.packagetype,
        )

    def from_archive(self, archive_path: str | Path, package: str = "local-archive") -> PackageSource:
        summary = self._llm_note(
            "You are the Fetcher Agent in LAMPS. Explain how a local archive should be handled safely.",
            f"Package label: {package}\nArchive path: {archive_path}",
            "Use the provided local archive as the package source and keep analysis static without installing or executing code.",
        )
        self.last_reasoning = {
            "llm_assisted": bool(self.llm_client and self.llm_client.available),
            "summary": summary,
            "source_type": "local",
        }
        return PackageSource(
            package=package,
            version=None,
            url=None,
            archive_path=str(archive_path),
            source_type="local",
        )

    def _llm_note(self, system: str, user: str, default: str) -> str:
        if not self.llm_client or not self.llm_client.available:
            return default
        return self.llm_client.complete_or_default(system, user, default)
