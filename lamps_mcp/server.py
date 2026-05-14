from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from lamps_mcp.tools import (
    evaluate_dataset_tool,
    list_reports_tool,
    prepare_codebert_splits_tool,
    read_report_tool,
    scan_archive_tool,
    scan_package_tool,
    train_codebert_tool,
)


mcp = FastMCP("lamps-mcp")


@mcp.tool()
def scan_package(package: str, classifier: str = "auto") -> dict[str, Any]:
    """Scan a package from PyPI without installing or executing it."""
    return scan_package_tool(package=package, classifier=classifier)


@mcp.tool()
def scan_archive(
    archive_path: str,
    package_name: str = "local-archive",
    classifier: str = "auto",
) -> dict[str, Any]:
    """Scan a local .tar.gz, .zip, or .whl archive without executing package code."""
    return scan_archive_tool(
        archive_path=archive_path,
        package_name=package_name,
        classifier=classifier,
    )


@mcp.tool()
def prepare_codebert_splits(
    csv_path: str = "dataset/D2-6000snippets.csv",
    output_dir: str = "CodeBERT_Classifier/data",
    code_column: str = "Setup.py",
    label_column: str | None = None,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 123456,
) -> dict[str, int]:
    """Convert the project CSV dataset into train, val, and test JSONL files."""
    return prepare_codebert_splits_tool(
        csv_path=csv_path,
        output_dir=output_dir,
        code_column=code_column,
        label_column=label_column,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        seed=seed,
    )


@mcp.tool()
def evaluate_dataset(
    dataset_path: str = "dataset/D2-6000snippets.csv",
    code_column: str = "Setup.py",
    label_column: str | None = None,
    max_samples: int = 50,
) -> dict[str, Any]:
    """Evaluate the heuristic classifier on a CSV dataset."""
    return evaluate_dataset_tool(
        dataset_path=dataset_path,
        code_column=code_column,
        label_column=label_column,
        max_samples=max_samples,
    )


@mcp.tool()
def train_codebert(
    train_path: str = "CodeBERT_Classifier/data/train.jsonl",
    val_path: str = "CodeBERT_Classifier/data/val.jsonl",
    test_path: str = "CodeBERT_Classifier/data/test.jsonl",
    output_dir: str = "CodeBERT_Classifier/checkpoint",
) -> dict[str, Any]:
    """Start CodeBERT fine-tuning from prepared JSONL splits."""
    return train_codebert_tool(
        train_path=train_path,
        val_path=val_path,
        test_path=test_path,
        output_dir=output_dir,
    )


@mcp.tool()
def list_reports(report_dir: str = "reports") -> dict[str, list[dict[str, Any]]]:
    """List generated JSON scan reports."""
    return list_reports_tool(report_dir=report_dir)


@mcp.tool()
def read_report(report_path: str) -> dict[str, Any]:
    """Read a generated JSON scan report."""
    return read_report_tool(report_path=report_path)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
