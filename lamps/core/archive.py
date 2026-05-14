from __future__ import annotations

from pathlib import Path
import tarfile
import zipfile

from lamps.core.file_filter import filter_python_files
from lamps.core.schemas import ExtractionResult


class UnsafeArchiveError(ValueError):
    """Raised when an archive member would escape the extraction directory."""


unsafe_archive_error = UnsafeArchiveError


def _ensure_within_directory(base: Path, target: Path) -> None:
    base_resolved = base.resolve()
    target_resolved = target.resolve()
    if base_resolved != target_resolved and base_resolved not in target_resolved.parents:
        raise UnsafeArchiveError(f"Unsafe archive member path: {target}")


def _safe_extract_tar(archive_path: Path, extract_dir: Path) -> list[Path]:
    extracted: list[Path] = []
    with tarfile.open(archive_path) as archive:
        for member in archive.getmembers():
            target = extract_dir / member.name
            _ensure_within_directory(extract_dir, target)
        archive.extractall(extract_dir)
        extracted = [extract_dir / member.name for member in archive.getmembers() if member.isfile()]
    return extracted


def _safe_extract_zip(archive_path: Path, extract_dir: Path) -> list[Path]:
    extracted: list[Path] = []
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            target = extract_dir / member.filename
            _ensure_within_directory(extract_dir, target)
        archive.extractall(extract_dir)
        extracted = [extract_dir / member.filename for member in archive.infolist() if not member.is_dir()]
    return extracted


def extract_archive_safely(archive_path: str | Path, extract_dir: str | Path) -> ExtractionResult:
    archive = Path(archive_path)
    destination = Path(extract_dir)
    destination.mkdir(parents=True, exist_ok=True)

    name = archive.name.lower()
    if tarfile.is_tarfile(archive):
        extracted_files = _safe_extract_tar(archive, destination)
    elif zipfile.is_zipfile(archive) or name.endswith(".whl"):
        extracted_files = _safe_extract_zip(archive, destination)
    else:
        raise ValueError(f"Unsupported archive format: {archive}")

    relative_files = [path.relative_to(destination) for path in extracted_files]
    python_files = filter_python_files(relative_files)
    skipped = sorted(
        path.as_posix() for path in relative_files if path.suffix == ".py" and path not in python_files
    )
    return ExtractionResult(
        archive_path=str(archive),
        extract_dir=str(destination),
        python_files=python_files,
        skipped_files=skipped,
        note=f"Extracted {len(python_files)} Python source files.",
    )
