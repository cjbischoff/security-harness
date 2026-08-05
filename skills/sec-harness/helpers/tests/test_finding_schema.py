import json
from pathlib import Path

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.schema import validate

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "references" / "finding.schema.json"
GOLDEN_PATH = Path(__file__).parent.parent / "fixtures" / "golden_raw_finding.json"


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def test_schema_file_exists_and_parses():
    schema = _schema()
    assert schema["type"] == "object"


def test_golden_fixture_validates_cleanly():
    data = json.loads(GOLDEN_PATH.read_text())
    assert validate(data, _schema()) == []


def test_required_fields_match_finding_dataclass_no_defaults():
    schema = _schema()
    assert set(schema["required"]) == {
        "id", "rule_id", "cls", "status", "severity", "file", "line", "message",
    }


def test_missing_required_field_is_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    del data["rule_id"]
    errors = validate(data, _schema())
    assert any("rule_id" in e for e in errors)


def test_bad_severity_enum_is_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    data["severity"] = "informational"
    errors = validate(data, _schema())
    assert any("severity" in e for e in errors)


def test_bad_status_enum_is_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    data["status"] = "not-a-real-status"
    errors = validate(data, _schema())
    assert any("status" in e for e in errors)


def test_hyphenated_needs_deployment_testing_status_is_valid():
    data = json.loads(GOLDEN_PATH.read_text())
    data["status"] = "needs-deployment-testing"
    assert validate(data, _schema()) == []


def test_wrong_type_for_line_is_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    data["line"] = "eighteen"
    errors = validate(data, _schema())
    assert any("line" in e for e in errors)


def test_unknown_extra_key_is_not_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    data["some_future_field"] = "value"
    assert validate(data, _schema()) == []


def test_default_finding_to_dict_validates_against_schema():
    f = Finding(
        id="F-0001",
        rule_id="test-rule",
        cls="sqli",
        status=FindingStatus.RAW,
        severity=Severity.HIGH,
        file="a.py",
        line=1,
        message="m",
    )
    assert validate(f.to_dict(), _schema()) == []
