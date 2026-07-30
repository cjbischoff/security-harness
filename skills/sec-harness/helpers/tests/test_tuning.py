"""Tests for adaptive-tuning scoreboard + ratchet + log."""

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.tuning import TuningLog, gap_report, is_improvement, signal_snapshot
from sec_harness.workspace import Workspace


def _f(id_, cls, file, status, sources):
    return Finding(id=id_, rule_id="r", cls=cls, status=status, severity=Severity.HIGH,
                   file=file, line=1, message="m", evidence_sources=sources)


def _c(id_, file, sources):  # a CONFIRMED finding
    return _f(id_, "sqli", file, FindingStatus.CONFIRMED, sources)


def test_signal_snapshot_shape():
    findings = [
        _f("A", "sqli", "a.go", FindingStatus.CONFIRMED, ["codeql:dataflow"]),
        _f("B", "ssrf", "b.go", FindingStatus.RAW, ["ast-grep:sink"]),
        _f("C", "xss", "c.go", FindingStatus.REJECTED, ["llm-inferred"]),
    ]
    s = signal_snapshot(findings)
    assert s["total"] == 3
    assert s["confirmed"] == 1
    assert len(s["confirmed_fingerprints"]) == 1
    assert s["coverage"]["files_with_receipt"] == 2          # A + B have tool receipts
    assert set(s["coverage"]["classes_covered"]) == {"sqli", "ssrf"}
    assert s["evidence"]["high"] == 2                         # A, B tool receipts
    assert s["evidence"]["low"] == 1                          # C llm-only


def test_improvement_new_confirmed_with_new_receipt():
    best = [_c("A", "a.go", ["codeql:sqli"])]
    cand = [_c("A", "a.go", ["codeql:sqli"]), _c("B", "b.go", ["semgrep:newrule"])]
    assert is_improvement(best, cand) is True


def test_no_improvement_when_prior_confirmed_lost():
    best = [_c("A", "a.go", ["codeql:sqli"])]
    cand = [_c("B", "b.go", ["semgrep:newrule"])]   # A gone
    assert is_improvement(best, cand) is False


def test_no_improvement_when_no_new():
    best = [_c("A", "a.go", ["codeql:sqli"])]
    assert is_improvement(best, list(best)) is False


def test_no_improvement_reroll_without_new_receipt():
    # new fingerprint (diff file/line) but only receipts already seen in best -> re-roll masquerade
    best = [_c("A", "a.go", ["codeql:sqli"])]
    cand = [_c("A", "a.go", ["codeql:sqli"]), _c("B", "b.go", ["codeql:sqli"])]
    assert is_improvement(best, cand) is False


def test_tuning_log_appends(tmp_path):
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    log = TuningLog(ws)
    assert log.entries() == []
    log.record(0, {"baseline": True}, {"confirmed": 2}, "baseline")
    log.record(1, {"added_rule": "x"}, {"confirmed": 3}, "accepted")
    e = log.entries()
    assert len(e) == 2
    assert e[0]["round"] == 0 and e[0]["verdict"] == "baseline"
    assert e[1]["round"] == 1 and e[1]["snapshot"]["confirmed"] == 3


def test_gap_report_partitions_attack_surface():
    findings = [
        _f("A", "sqli", "a.js", FindingStatus.CONFIRMED, ["semgrep:sqli"]),   # sqli covered by a tool
        _f("B", "xss", "b.js", FindingStatus.RAW, ["llm-inferred"]),          # xss only llm -> NOT covered
    ]
    g = gap_report(findings, ["sqli", "xss", "ssrf"])
    assert g["covered_classes"] == ["sqli"]
    assert g["uncovered_classes"] == ["ssrf", "xss"]     # xss has no tool receipt; ssrf has nothing
    assert g["files_with_receipt"] == 1
