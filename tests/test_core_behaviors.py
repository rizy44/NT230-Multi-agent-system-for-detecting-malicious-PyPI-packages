import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest


def test_file_filter_keeps_python_sources_and_skips_noise():
    from lamps.core.file_filter import filter_python_files

    paths = [
        Path("pkg/__init__.py"),
        Path("pkg/core.py"),
        Path("tests/test_core.py"),
        Path("docs/conf.py"),
        Path("examples/demo.py"),
        Path("pkg.egg-info/SOURCES.txt"),
        Path("pkg/__pycache__/core.py"),
        Path("README.md"),
    ]

    assert filter_python_files(paths) == [
        Path("pkg/__init__.py"),
        Path("pkg/core.py"),
    ]


def test_safe_extract_tar_blocks_path_traversal(tmp_path):
    from lamps.core.archive import unsafe_archive_error, extract_archive_safely

    archive_path = tmp_path / "evil.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        data = b"print('owned')"
        info = tarfile.TarInfo("../evil.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    with pytest.raises(unsafe_archive_error):
        extract_archive_safely(archive_path, tmp_path / "out")


def test_safe_extract_zip_and_return_python_files(tmp_path):
    from lamps.core.archive import extract_archive_safely

    archive_path = tmp_path / "pkg.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("pkg/__init__.py", "")
        archive.writestr("pkg/main.py", "print('ok')")
        archive.writestr("tests/test_main.py", "print('skip')")
        archive.writestr("README.md", "skip")

    result = extract_archive_safely(archive_path, tmp_path / "out")

    assert [p.as_posix() for p in result.python_files] == [
        "pkg/__init__.py",
        "pkg/main.py",
    ]


def test_heuristic_classifier_flags_encoded_subprocess_behavior():
    from lamps.core.codebert import HeuristicClassifier

    code = "import base64, subprocess\nsubprocess.Popen(base64.b64decode('abc'))"

    result = HeuristicClassifier().classify_code(code, "setup.py")

    assert result.label == "malicious"
    assert result.score >= 0.8
    assert "base64" in result.signals
    assert "subprocess" in result.signals


def test_verdict_policy_marks_package_malicious_if_any_file_is_malicious():
    from lamps.agents.verdict import VerdictAgent
    from lamps.core.schemas import FileClassification

    results = [
        FileClassification(path="pkg/__init__.py", label="benign", score=0.95, signals=[]),
        FileClassification(path="setup.py", label="malicious", score=0.91, signals=["subprocess"]),
    ]

    report = VerdictAgent().decide("demo", "1.0.0", results)

    assert report.verdict == "malicious"
    assert report.malicious_files == ["setup.py"]
    assert "setup.py" in report.rationale


def test_report_serializes_required_json_fields():
    from lamps.core.schemas import FileClassification, ScanReport

    report = ScanReport(
        package="demo",
        version="1.0.0",
        verdict="benign",
        malicious_files=[],
        files_analyzed=1,
        file_results=[
            FileClassification(path="demo/__init__.py", label="benign", score=0.99, signals=[])
        ],
        rationale="All analyzed Python files were classified as benign.",
        agent_trace={"fetcher": {}, "extractor": {}, "classifier": {}, "verdict": {}},
    )

    payload = json.loads(report.to_json())

    assert payload["verdict"] == "benign"
    assert payload["file_results"][0]["label"] == "benign"
    assert set(payload["agent_trace"]) == {"fetcher", "extractor", "classifier", "verdict"}


def test_pypi_client_prefers_sdist_over_wheel():
    from lamps.core.pypi_client import PyPIClient

    class FakeClient(PyPIClient):
        def fetch_metadata(self, package_name):
            return {
                "info": {"version": "1.2.3"},
                "urls": [
                    {
                        "packagetype": "bdist_wheel",
                        "url": "https://files.pythonhosted.org/pkg/demo-1.2.3.whl",
                    },
                    {
                        "packagetype": "sdist",
                        "url": "https://files.pythonhosted.org/pkg/demo-1.2.3.tar.gz",
                    },
                ],
            }

    artifact = FakeClient().choose_artifact("demo")

    assert artifact.version == "1.2.3"
    assert artifact.packagetype == "sdist"
    assert artifact.filename == "demo-1.2.3.tar.gz"


def test_pipeline_scans_local_archive_with_heuristic_classifier(tmp_path, monkeypatch):
    from lamps.core.config import Settings
    from lamps.core.pipeline import LAMPSPipeline

    archive_path = tmp_path / "demo.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        code = b"import base64, subprocess\nsubprocess.Popen(base64.b64decode('abc'))"
        info = tarfile.TarInfo("demo/setup.py")
        info.size = len(code)
        tar.addfile(info, io.BytesIO(code))

    settings = Settings(
        llm_api_key=None,
        llm_api_base="https://api.openai.com/v1",
        llm_model="unused",
        codebert_model_path=tmp_path / "missing-model",
        download_dir=tmp_path / "downloads",
        extract_dir=tmp_path / "extracted",
        report_dir=tmp_path / "reports",
    )

    report = LAMPSPipeline(settings, classifier_mode="auto").scan_archive(archive_path, package="demo")

    assert report.verdict == "malicious"
    assert report.malicious_files == ["demo/setup.py"]
    assert (tmp_path / "reports" / "demo-report.json").exists()


def test_csv_to_jsonl_auto_detects_label_column(tmp_path):
    from lamps.evaluation.prepare_dataset import csv_to_jsonl

    csv_path = tmp_path / "data.csv"
    out_path = tmp_path / "data.jsonl"
    csv_path.write_text('Serial,Setup.py,Label\n1,"print(1)",1\n2,"print(2)",0\n', encoding="utf-8")

    csv_to_jsonl(csv_path, out_path)

    lines = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
    assert lines == [
        {"idx": "0", "func": "print(1)", "target": 1},
        {"idx": "1", "func": "print(2)", "target": 0},
    ]


def test_create_codebert_splits_writes_train_val_test_jsonl(tmp_path):
    from lamps.evaluation.prepare_dataset import create_codebert_splits

    csv_path = tmp_path / "dataset.csv"
    rows = ["Serial,Package,Version,Setup.py,Label"]
    for index in range(20):
        label = 1 if index % 2 else 0
        rows.append(f'{index},pkg{index},1.0,"print({index})",{label}')
    csv_path.write_text("\n".join(rows), encoding="utf-8")

    summary = create_codebert_splits(
        csv_path=csv_path,
        output_dir=tmp_path / "codebert_data",
        train_ratio=0.7,
        val_ratio=0.15,
        test_ratio=0.15,
        seed=123456,
    )

    assert summary["total"] == 20
    assert summary["train"] == 14
    assert summary["val"] == 3
    assert summary["test"] == 3
    for split in ("train", "val", "test"):
        assert (tmp_path / "codebert_data" / f"{split}.jsonl").exists()

    train_items = [
        json.loads(line)
        for line in (tmp_path / "codebert_data" / "train.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert set(train_items[0]) == {"idx", "func", "target"}
    assert {item["target"] for item in train_items} == {0, 1}
