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
        artifact = self.pypi_client.choose_artifact(normalized)
        archive_path = self.pypi_client.download_artifact(artifact, download_dir)
        return PackageSource(
            package=artifact.package,
            version=artifact.version,
            url=artifact.url,
            archive_path=str(archive_path),
            source_type=artifact.packagetype,
        )

    def from_archive(self, archive_path: str | Path, package: str = "local-archive") -> PackageSource:
        return PackageSource(
            package=package,
            version=None,
            url=None,
            archive_path=str(archive_path),
            source_type="local",
        )
