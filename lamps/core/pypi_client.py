from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import json


class PyPIClientError(RuntimeError):
    pass


@dataclass(slots=True)
class PyPIArtifact:
    package: str
    version: str
    url: str
    packagetype: str
    filename: str


class PyPIClient:
    def __init__(self, base_url: str = "https://pypi.org/pypi", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def fetch_metadata(self, package_name: str) -> dict:
        url = f"{self.base_url}/{package_name}/json"
        request = Request(url, headers={"User-Agent": "lamps-replica/0.1"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise PyPIClientError(f"Could not fetch PyPI metadata for {package_name}: {exc}") from exc

    def choose_artifact(self, package_name: str) -> PyPIArtifact:
        metadata = self.fetch_metadata(package_name)
        urls = metadata.get("urls", [])
        info = metadata.get("info", {})
        version = info.get("version")
        if not urls or not version:
            raise PyPIClientError(f"PyPI metadata for {package_name} does not contain downloadable artifacts.")

        chosen = None
        for candidate_type in ("sdist", "bdist_wheel"):
            chosen = next((entry for entry in urls if entry.get("packagetype") == candidate_type), None)
            if chosen:
                break
        if not chosen:
            raise PyPIClientError(f"No source distribution or wheel found for {package_name}.")

        url = chosen["url"]
        filename = Path(urlparse(url).path).name
        return PyPIArtifact(
            package=package_name,
            version=version,
            url=url,
            packagetype=chosen.get("packagetype", "unknown"),
            filename=filename,
        )

    def download_artifact(self, artifact: PyPIArtifact, download_dir: str | Path) -> Path:
        destination = Path(download_dir)
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / artifact.filename
        request = Request(artifact.url, headers={"User-Agent": "lamps-replica/0.1"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                target.write_bytes(response.read())
        except Exception as exc:
            raise PyPIClientError(f"Could not download {artifact.url}: {exc}") from exc
        return target
