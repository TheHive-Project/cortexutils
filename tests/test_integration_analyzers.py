import json
import tempfile
from contextlib import contextmanager
from pathlib import Path

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


@contextmanager
def init_job_directory(input_obj: dict | None = None):
    """Context manager that yields a temporary job directory path, then cleans up."""
    temp_dir = tempfile.TemporaryDirectory()
    job_dir = Path(temp_dir.name)

    try:
        input_dir = job_dir / "input"
        input_dir.mkdir()

        if input_obj is None:
            input_obj = DEFAULT_INPUT

        with open(input_dir / "input.json", "w") as f:
            json.dump(input_obj, f)

        output_dir = job_dir / "output"
        output_dir.mkdir()

        yield job_dir

    finally:
        temp_dir.cleanup()


def load_output(job_directory: Path) -> dict:
    with open(job_directory / "output" / "output.json") as output_file:
        output = json.load(output_file)
        return output


def test_simple_analyzer_success():
    with init_job_directory() as job_directory:
        Analyzer(job_directory).report({})
        output = load_output(job_directory)
    assert output == DEFAULT_OUTPUT


def test_simple_analyzer_error():

    error_msg = "test analyzer error"
    with init_job_directory() as job_directory:
        with pytest.raises(SystemExit):
            Analyzer(job_directory).error(error_msg)
        output = load_output(job_directory)

    assert output == {
        "success": False,
        "input": DEFAULT_INPUT,
        "errorMessage": error_msg,
    }


def test_analyzer_report_with_summary_and_taxonomies():
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

    with init_job_directory() as job_directory:
        full_report = {}
        TestAnalyzer(job_directory).report(full_report)
        output = load_output(job_directory)

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


def test_analyzer_report_with_operations():
    class TestAnalyzer(Analyzer):
        def operations(self, raw):
            return [self.build_operation(op_type="DummyOperation", dummy="parameter")]

    with init_job_directory() as job_directory:
        TestAnalyzer(job_directory).report({})
        output = load_output(job_directory)

    assert output == {
        **DEFAULT_OUTPUT,
        "operations": [{"type": "DummyOperation", "dummy": "parameter"}],
    }


def test_analyzer_report_with_extractable_artifacts():
    string_ip_artifact = "11.22.33.44"
    list_ip_artifacts = ["10.20.30.40", "20.30.40.50"]
    dict_item_ip_artifact = "100.100.100.100"

    report = {
        "simple-ip": string_ip_artifact,
        "list-of-ips": list_ip_artifacts,
        "dict-with-ip": {"just-an-ip": dict_item_ip_artifact},
    }

    with init_job_directory() as job_directory:
        Analyzer(job_directory).report(report)
        output = load_output(job_directory)

    assert output == {
        **DEFAULT_OUTPUT,
        "artifacts": [
            {"data": ip, "dataType": "ip"}
            for ip in [string_ip_artifact, *list_ip_artifacts, dict_item_ip_artifact]
        ],
        "full": report,
    }


def test_analyzer_error_for_invalid_input():

    empty_input = {}
    with init_job_directory(empty_input) as job_directory:
        with pytest.raises(SystemExit):
            Analyzer(job_directory)
        output = load_output(job_directory)

    assert output == {
        "success": False,
        "input": empty_input,
        "errorMessage": "Missing dataType field",
    }

    generic_input_without_data = {"dataType": "ip"}
    with init_job_directory(generic_input_without_data) as job_directory:
        with pytest.raises(SystemExit):
            Analyzer(job_directory).report({})
        output = load_output(job_directory)

    assert output == {
        "success": False,
        "input": generic_input_without_data,
        "errorMessage": "Missing data field",
    }

    file_input_without_filename = {"dataType": "file"}
    with init_job_directory(file_input_without_filename) as job_directory:
        with pytest.raises(SystemExit):
            Analyzer(job_directory).report({})
        output = load_output(job_directory)

    assert output == {
        "success": False,
        "input": file_input_without_filename,
        "errorMessage": "Missing filename.",
    }
