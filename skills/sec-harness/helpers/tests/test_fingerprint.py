"""Tests for stable finding fingerprints + cross-pass diffing."""

from sec_harness.fingerprint import diff_findings, fingerprint
from sec_harness.models import Finding, FindingStatus, Severity


def _f(rule, cls, file, line):
    return Finding(id="x", rule_id=rule, cls=cls, status=FindingStatus.RAW,
                   severity=Severity.HIGH, file=file, line=line, message="m")


def test_fingerprint_stable_and_discriminating():
    a = _f("r", "sqli", "a.py", 10)
    assert fingerprint(a) == fingerprint(_f("r", "sqli", "a.py", 10))   # stable
    assert fingerprint(a) != fingerprint(_f("r", "sqli", "a.py", 11))   # line matters
    assert len(fingerprint(a)) == 12


def test_diff_findings_partitions():
    prev = [_f("r", "sqli", "a.py", 10), _f("r", "secrets", "b.py", 5)]
    cur = [_f("r", "sqli", "a.py", 10), _f("r", "ssrf", "c.py", 7)]
    d = diff_findings(prev, cur)
    assert fingerprint(_f("r", "ssrf", "c.py", 7)) in d["new"]
    assert fingerprint(_f("r", "secrets", "b.py", 5)) in d["resolved"]
    assert fingerprint(_f("r", "sqli", "a.py", 10)) in d["still_flagged"]
