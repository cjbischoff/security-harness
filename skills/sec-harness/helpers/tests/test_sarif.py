"""Tests for SARIF emission."""

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.sarif import to_sarif


def _f(sev):
    return Finding(id="F-0001", rule_id="r", cls="sqli", status=FindingStatus.CONFIRMED,
                   severity=sev, file="app.py", line=18, message="SQLi")


def test_sarif_shape_and_level_mapping():
    doc = to_sarif([_f(Severity.HIGH)])
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "sec-harness"
    res = run["results"][0]
    assert res["ruleId"] == "r"
    assert res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 18


def test_sarif_level_for_medium_and_low():
    assert to_sarif([_f(Severity.MEDIUM)])["runs"][0]["results"][0]["level"] == "warning"
    assert to_sarif([_f(Severity.LOW)])["runs"][0]["results"][0]["level"] == "note"
