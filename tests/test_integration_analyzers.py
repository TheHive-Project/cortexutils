import json
from pathlib import Path
from typing import Callable

import pytest

from cortexutils.analyzer import Analyzer

DEFAULT_INPUT = {
    "dataType": "ip",
    "data": "1.2.3.4",
}

DEFAULT_OUTPUT = {
    "success": True,
    "full": {},
    "summary": {},
    "artifacts": [],
    "operations": [],
}


@pytest.fixture(scope="function")
def job_directory(tmp_path: Path) -> Path:
    """Fixture to initialize the actual test job's directory."""

    job_dir = tmp_path

    input_dir = job_dir / "input"
    input_dir.mkdir()

    with open(input_dir / "input.json", "w") as f:
        json.dump(DEFAULT_INPUT, f)

    output_dir = job_dir / "output"
    output_dir.mkdir()

    print(job_dir)
    return job_dir


@pytest.fixture
def add_job_input(job_directory: Path) -> Callable[[dict], None]:
    """Factory fixture to specify a custom input.json for the actual test job."""

    def _add_job_input(input_obj: dict):

        with open(job_directory / "input" / "input.json", "w") as f:
            print(f.name)
            json.dump(input_obj, f)

    return _add_job_input


@pytest.fixture
def load_job_output(job_directory: Path) -> Callable[[], dict]:
    """Factory fixture to load the actual test job's output.json."""

    def _load_job_output() -> dict:
        with open(job_directory / "output" / "output.json") as output_file:
            output = json.load(output_file)
            return output

    return _load_job_output


def test_simple_analyzer_success(job_directory, load_job_output):
    Analyzer(job_directory).report({})
    output = load_job_output()
    assert output == DEFAULT_OUTPUT


def test_simple_analyzer_error(job_directory, load_job_output):
    error_msg = "test analyzer error"
    with pytest.raises(SystemExit):
        Analyzer(job_directory).error(error_msg)

    output = load_job_output()
    assert output == {
        "success": False,
        "input": DEFAULT_INPUT,
        "errorMessage": error_msg,
    }


def test_analyzer_report_with_summary_and_taxonomies(job_directory, load_job_output):
    class TestAnalyzer(Analyzer):
        def summary(self, raw):
            taxonomies = []
            for taxonomy_level in ["info", "safe", "suspicious", "malicious", "n/a"]:
                taxonomies.append(
                    self.build_taxonomy(
                        level=taxonomy_level,
                        namespace="cortexutils",
                        predicate="integration-tests",
                        value="analyzer",
                    )
                )
            return {"taxonomies": taxonomies, "raw": raw}

    full_report = {}
    TestAnalyzer(job_directory).report(full_report)
    output = load_job_output()

    assert output == {
        **DEFAULT_OUTPUT,
        "summary": {
            "raw": full_report,
            "taxonomies": [
                {
                    "level": level,
                    "namespace": "cortexutils",
                    "predicate": "integration-tests",
                    "value": "analyzer",
                }
                for level in ["info", "safe", "suspicious", "malicious", "info"]
            ],
        },
    }


def test_analyzer_report_with_operations(job_directory, load_job_output):
    class TestAnalyzer(Analyzer):
        def operations(self, raw):
            return [self.build_operation(op_type="DummyOperation", dummy="parameter")]

    TestAnalyzer(job_directory).report({})
    output = load_job_output()

    assert output == {
        **DEFAULT_OUTPUT,
        "operations": [{"type": "DummyOperation", "dummy": "parameter"}],
    }


def test_analyzer_report_with_extractable_artifacts(job_directory, load_job_output):
    string_ip_artifact = "11.22.33.44"
    list_ip_artifacts = ["10.20.30.40", "20.30.40.50"]
    dict_item_ip_artifact = "100.100.100.100"

    report = {
        "simple-ip": string_ip_artifact,
        "list-of-ips": list_ip_artifacts,
        "dict-with-ip": {"just-an-ip": dict_item_ip_artifact},
    }

    Analyzer(job_directory).report(report)
    output = load_job_output()

    assert output == {
        **DEFAULT_OUTPUT,
        "artifacts": [
            {"data": ip, "dataType": "ip"}
            for ip in [string_ip_artifact, *list_ip_artifacts, dict_item_ip_artifact]
        ],
        "full": report,
    }


def test_analyzer_error_for_invalid_input(
    job_directory, add_job_input, load_job_output
):

    empty_input = {}
    add_job_input(empty_input)
    with pytest.raises(SystemExit):
        Analyzer(job_directory)
    output = load_job_output()

    assert output == {
        "success": False,
        "input": empty_input,
        "errorMessage": "Missing dataType field",
    }

    generic_input_without_data = {"dataType": "ip"}
    add_job_input(generic_input_without_data)
    with pytest.raises(SystemExit):
        Analyzer(job_directory).report({})
    output = load_job_output()

    assert output == {
        "success": False,
        "input": generic_input_without_data,
        "errorMessage": "Missing data field",
    }

    file_input_without_filename = {"dataType": "file"}
    add_job_input(file_input_without_filename)
    with pytest.raises(SystemExit):
        Analyzer(job_directory).report({})
    output = load_job_output()

    assert output == {
        "success": False,
        "input": file_input_without_filename,
        "errorMessage": "Missing filename.",
    }
