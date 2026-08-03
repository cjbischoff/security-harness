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


def _f2(line, *, fp=None, rule="r", cls="sqli", file="a/b.py"):
    from sec_harness.models import Finding, FindingStatus, Severity
    return Finding(id="F-1", rule_id=rule, cls=cls, status=FindingStatus.RAW,
                   severity=Severity.HIGH, file=file, line=line, message="m", fingerprint=fp)


def test_fingerprint_with_anchor_is_line_independent():
    from sec_harness.fingerprint import fingerprint
    a = fingerprint(_f2(10), anchor="handler")
    b = fingerprint(_f2(42), anchor="handler")   # same symbol, moved lines
    assert a == b


def test_fingerprint_without_anchor_falls_back_to_file_line():
    from sec_harness.fingerprint import fingerprint
    assert fingerprint(_f2(10)) != fingerprint(_f2(11))   # distinct lines differ


def test_diff_findings_uses_stamped_fingerprint():
    from sec_harness.fingerprint import diff_findings
    prev = [_f2(10, fp="deadbeef0000")]
    cur = [_f2(88, fp="deadbeef0000")]   # moved, same stamped identity
    result = diff_findings(prev, cur)
    assert result["still_flagged"] == ["deadbeef0000"]
    assert result["new"] == [] and result["resolved"] == []
