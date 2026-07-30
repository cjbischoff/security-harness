"""Tests for noise-floor exclusions."""

from sec_harness.exclusions import Exclusions, apply_exclusions, load_exclusions
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace


def _f(id_, cls, file, rule="r"):
    return Finding(id=id_, rule_id=rule, cls=cls, status=FindingStatus.CANDIDATE,
                   severity=Severity.LOW, file=file, line=1, message="m")


def test_apply_exclusions_by_class_rule_path():
    findings = [_f("A", "log-injection", "a.go"), _f("B", "sqli", "b.go", rule="noisy"),
                _f("C", "sqli", "vendor/x.go"), _f("D", "sqli", "keep.go")]
    ex = Exclusions(rule_ids={"noisy"}, paths=["vendor/*"], classes={"log-injection"})
    kept, dropped = apply_exclusions(findings, ex)
    assert {f.id for f in kept} == {"D"}
    assert {f.id for f in dropped} == {"A", "B", "C"}


def test_load_exclusions_missing_is_empty(tmp_path):
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    ex = load_exclusions(ws)
    assert ex.rule_ids == set() and ex.paths == [] and ex.classes == set()


def test_load_exclusions_from_file(tmp_path):
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    (ws.kb / "exclusions.json").write_text('{"rule_ids":["r1"],"paths":["t/*"],"classes":["xss"],"reason":"noise"}')
    ex = load_exclusions(ws)
    assert ex.rule_ids == {"r1"} and ex.paths == ["t/*"] and ex.classes == {"xss"}
