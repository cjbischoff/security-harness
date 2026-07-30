"""Tests for finding normalization / dedup."""

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.normalize import normalize


def _f(rule, cls, file, line, sev):
    return Finding(id="C-x", rule_id=rule, cls=cls, status=FindingStatus.CANDIDATE,
                   severity=sev, file=file, line=line, message="m")


def test_dedup_by_file_line_class_keeps_highest_severity():
    out = normalize([
        _f("r1", "sqli", "a.py", 10, Severity.MEDIUM),
        _f("r2", "sqli", "a.py", 10, Severity.HIGH),
    ])
    assert len(out) == 1
    assert out[0].severity is Severity.HIGH


def test_stable_ids_assigned_in_sorted_order():
    out = normalize([
        _f("r", "secrets", "b.py", 5, Severity.HIGH),
        _f("r", "sqli", "a.py", 20, Severity.HIGH),
    ])
    assert [x.id for x in out] == ["F-0001", "F-0002"]
    assert out[0].file == "a.py"  # sorted first
