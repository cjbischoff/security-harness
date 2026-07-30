"""Tests for F5 rule_gaps, F6 detection_coverage, F7 coverage_guide."""
from sec_harness.coverage_guide import coverage_complete, should_stop
from sec_harness.detection_coverage import generate, known_classes
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.rule_gaps import is_rule_originated, load_rule_gaps, record_rule_gaps
from sec_harness.workspace import Workspace, write_findings


def _f(id_, status, sources, cls="authz"):
    return Finding(id=id_, rule_id="r", cls=cls, status=status, severity=Severity.HIGH,
                   file="a.py", line=5, message="m", evidence_sources=sources, fingerprint=id_)


# F5
def test_is_rule_originated():
    assert is_rule_originated(_f("A", FindingStatus.CONFIRMED, ["semgrep:x"]))
    assert is_rule_originated(_f("A", FindingStatus.CONFIRMED, ["sca:osv:CVE"]))
    assert not is_rule_originated(_f("A", FindingStatus.CONFIRMED, ["ripgrep:x", "llm-claimed:y"]))


def test_record_rule_gaps(tmp_path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [
        _f("G1", FindingStatus.CONFIRMED, ["structural-index:callers", "llm-claimed:reach"]),  # hunt-found -> gap
        _f("G2", FindingStatus.CONFIRMED, ["semgrep:sqli"]),                                    # rule-found -> not a gap
        _f("G3", FindingStatus.REJECTED, ["llm-claimed:x"]),                                     # not confirmed
    ])
    n = record_rule_gaps(ws, ts="2026-07-30")
    assert n == 1
    gaps = load_rule_gaps(ws)
    assert [g["fingerprint"] for g in gaps] == ["G1"]
    # idempotent: re-running records no new gap
    assert record_rule_gaps(ws) == 0


# F7
def test_coverage_and_stop():
    surface = ["sqli", "authz", "deps"]
    assert coverage_complete(surface, {"sqli", "authz"}) is True   # deps excluded
    assert coverage_complete(surface, {"sqli"}) is False
    assert should_stop(surface, {"sqli", "authz"}, 0) is True      # covered + zero new
    assert should_stop(surface, {"sqli", "authz"}, 3) is False     # covered but still yielding
    assert should_stop(surface, {"sqli"}, 0) is False              # not covered


# F6
def test_detection_coverage_lists_every_class():
    md = generate()
    for cls in known_classes():
        assert cls in md, f"class {cls} missing from coverage doc"
    assert "Known limitations" in md and "no PHP" in md
