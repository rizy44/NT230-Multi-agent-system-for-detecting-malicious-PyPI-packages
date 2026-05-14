import io
import json
import tarfile


def test_scan_archive_args_defaults():
    from lamps_mcp.schemas import ScanArchiveArgs

    args = ScanArchiveArgs(archive_path="sample.tar.gz")

    assert args.archive_path == "sample.tar.gz"
    assert args.package_name == "local-archive"
    assert args.classifier == "auto"


def test_summarize_report_includes_report_path():
    from lamps.core.schemas import FileClassification, ScanReport
    from lamps_mcp.tools import summarize_report

    report = ScanReport(
        package="demo",
        version="1.0.0",
        verdict="malicious",
        malicious_files=["setup.py"],
        files_analyzed=1,
        file_results=[FileClassification(path="setup.py", label="malicious", score=0.9)],
        rationale="setup.py was flagged.",
        agent_trace={"fetcher": {}, "extractor": {}, "classifier": {}, "verdict": {}},
    )

    summary = summarize_report(report, "reports/demo-report.json")

    assert summary["package"] == "demo"
    assert summary["verdict"] == "malicious"
    assert summary["report_path"] == "reports/demo-report.json"


def test_list_reports_and_read_report(tmp_path):
    from lamps_mcp.tools import list_reports_tool, read_report_tool

    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report_path = report_dir / "demo-report.json"
    report_payload = {
        "package": "demo",
        "version": "1.0.0",
        "verdict": "malicious",
        "malicious_files": ["setup.py"],
        "files_analyzed": 1,
        "file_results": [],
        "rationale": "setup.py was flagged.",
        "agent_trace": {},
    }
    report_path.write_text(json.dumps(report_payload), encoding="utf-8")

    listed = list_reports_tool(str(report_dir))
    loaded = read_report_tool(str(report_path))

    assert listed == {
        "reports": [
            {
                "path": str(report_path),
                "package": "demo",
                "verdict": "malicious",
            }
        ]
    }
    assert loaded == report_payload


def test_prepare_codebert_splits_tool_writes_splits(tmp_path):
    from lamps_mcp.tools import prepare_codebert_splits_tool

    csv_path = tmp_path / "dataset.csv"
    rows = ["Serial,Package,Version,Setup.py,Label"]
    for index in range(20):
        label = 1 if index % 2 else 0
        rows.append(f'{index},pkg{index},1.0,"print({index})",{label}')
    csv_path.write_text("\n".join(rows), encoding="utf-8")

    summary = prepare_codebert_splits_tool(
        csv_path=str(csv_path),
        output_dir=str(tmp_path / "splits"),
        train_ratio=0.7,
        val_ratio=0.15,
        test_ratio=0.15,
    )

    assert summary == {
        "total": 20,
        "train": 14,
        "val": 3,
        "test": 3,
        "benign": 10,
        "malicious": 10,
    }
    assert (tmp_path / "splits" / "train.jsonl").exists()
    assert (tmp_path / "splits" / "val.jsonl").exists()
    assert (tmp_path / "splits" / "test.jsonl").exists()


def test_evaluate_dataset_tool_returns_metrics(tmp_path):
    from lamps_mcp.tools import evaluate_dataset_tool

    csv_path = tmp_path / "dataset.csv"
    csv_path.write_text(
        'Serial,Setup.py,Label\n'
        '1,"import base64, subprocess\nsubprocess.Popen(base64.b64decode(' "'abc'" '))",1\n'
        '2,"print(2)",0\n',
        encoding="utf-8",
    )

    metrics = evaluate_dataset_tool(dataset_path=str(csv_path), max_samples=2)

    assert set(metrics) == {
        "accuracy",
        "precision",
        "recall",
        "f1",
        "balanced_accuracy",
        "confusion_matrix",
    }
    assert metrics["confusion_matrix"] == {"tp": 1, "tn": 1, "fp": 0, "fn": 0}


def test_scan_archive_tool_uses_heuristic_without_api_key(tmp_path, monkeypatch):
    from lamps_mcp.tools import scan_archive_tool

    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("CODEBERT_MODEL_PATH", str(tmp_path / "missing-model"))
    monkeypatch.setenv("DOWNLOAD_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("EXTRACT_DIR", str(tmp_path / "extracted"))
    monkeypatch.setenv("REPORT_DIR", str(tmp_path / "reports"))

    archive_path = tmp_path / "demo.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        code = b"import base64, subprocess\nsubprocess.Popen(base64.b64decode('abc'))"
        info = tarfile.TarInfo("demo/setup.py")
        info.size = len(code)
        tar.addfile(info, io.BytesIO(code))

    summary = scan_archive_tool(str(archive_path), package_name="demo", classifier="heuristic")

    assert summary["package"] == "demo"
    assert summary["verdict"] == "malicious"
    assert summary["malicious_files"] == ["demo/setup.py"]
    assert summary["report_path"] == str(tmp_path / "reports" / "demo-report.json")
