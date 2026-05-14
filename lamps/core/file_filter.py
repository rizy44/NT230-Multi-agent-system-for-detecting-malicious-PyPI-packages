from __future__ import annotations

from pathlib import Path


SKIPPED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "test",
    "tests",
    "testing",
    "docs",
    "doc",
    "examples",
    "example",
    "benchmarks",
    "benchmark",
}


def should_analyze_python_file(path: Path) -> bool:
    if path.suffix != ".py":
        return False
    lowered_parts = {part.lower() for part in path.parts}
    if lowered_parts & SKIPPED_PARTS:
        return False
    if any(part.lower().endswith(".egg-info") for part in path.parts):
        return False
    return True


def filter_python_files(paths: list[Path]) -> list[Path]:
    return sorted((p for p in paths if should_analyze_python_file(p)), key=lambda p: p.as_posix())
