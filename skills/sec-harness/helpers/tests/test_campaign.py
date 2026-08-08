"""Tests for campaign pass lifecycle."""

from __future__ import annotations

from pathlib import Path

from sec_harness.campaign import pass_report, promote_deps, record_stage
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.state import begin_pass, load_state
from sec_harness.workspace import Workspace, read_findings, write_findings


def _f(id_, status):
    return Finding(id=id_, rule_id="r", cls="sqli", status=status, severity=Severity.HIGH,
                   file="app.py", line=1, message="m")


def test_record_stage_persists_and_enables_increment(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    begin_pass(ws, "sha1")
    record_stage(ws, "prefilter")
    assert load_state(ws).stages["prefilter"] == "done"
    # a completed pass -> next begin_pass increments and clears stages
    st2 = begin_pass(ws, "sha2")
    assert st2.pass_number == 2
    assert st2.stages == {}


def test_pass_report_summarizes(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    begin_pass(ws, "shaX")
    record_stage(ws, "prefilter")
    write_findings(ws, [_f("F-0001", FindingStatus.CONFIRMED), _f("F-0002", FindingStatus.REJECTED)])
    rep = pass_report(ws)
    assert rep["pass_number"] == 1
    assert rep["active_sha"] == "shaX"
    assert rep["stages"]["prefilter"] == "done"
    assert rep["findings_by_status"]["confirmed"] == 1
    assert rep["findings_by_status"]["rejected"] == 1


def test_carry_forward_stales_settled_on_changed_file(tmp_path):
    from sec_harness.campaign import carry_forward

    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [
        Finding(id="F-0001", rule_id="r", cls="sqli", status=FindingStatus.CONFIRMED,
                severity=Severity.HIGH, file="app.py", line=1, message="m"),
        Finding(id="F-0002", rule_id="r", cls="secrets", status=FindingStatus.FIXED,
                severity=Severity.HIGH, file="util.py", line=1, message="m"),
    ])
    result = carry_forward(ws, ["app.py"])
    assert result == {"staled": 1, "kept": 1}
    from sec_harness.workspace import read_findings as rf
    by_id = {f.id: f for f in rf(ws)}
    assert by_id["F-0001"].status is FindingStatus.STALE      # file changed -> re-examine
    assert by_id["F-0002"].status is FindingStatus.FIXED      # unchanged file -> kept


def test_carry_forward_ignores_non_settled(tmp_path):
    from sec_harness.campaign import carry_forward

    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [
        Finding(id="F-0003", rule_id="r", cls="sqli", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=1, message="m"),
    ])
    assert carry_forward(ws, ["app.py"]) == {"staled": 0, "kept": 0}  # RAW not settled


def _dep(
    id: str = "C-1",
    file: str = "package-lock.json",
    evidence_sources: list[str] | None = None,
) -> Finding:
    return Finding(
        id=id,
        rule_id="osv:GHSA-x",
        cls="deps",
        status=FindingStatus.CANDIDATE,
        severity=Severity.HIGH,
        file=file,
        line=1,
        message="vuln dep",
        evidence_sources=evidence_sources if evidence_sources is not None else ["sca:osv:GHSA-x"],
    )


def test_promote_deps_confirms_with_sca_receipt(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_dep()])
    n = promote_deps(ws)
    f = read_findings(ws)[0]
    assert n == 1
    assert f.status is FindingStatus.CONFIRMED
    assert f.reachability == {"reachable": False,
                              "blocker": "dev-build-dependency-not-runtime-verified", "chain": []}


def test_promote_deps_ignores_non_sca_candidate(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_dep(id="C-2", evidence_sources=["llm-claimed:dep"])])
    assert promote_deps(ws) == 0
    assert read_findings(ws)[0].status is FindingStatus.CANDIDATE


def test_promote_deps_non_lockfile_marks_unverified(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_dep(id="C-3", file="src/vendor/thing.go")])
    promote_deps(ws)
    f = read_findings(ws)[0]
    assert f.status is FindingStatus.CONFIRMED
    assert f.reachability == {"reachable": None, "blocker": None, "chain": []}


def test_promote_runtime_dependent(tmp_path):
    from sec_harness.campaign import promote_runtime_dependent
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.workspace import Workspace, read_findings, write_findings
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    def f(id_, rd, status=FindingStatus.RAW):
        return Finding(id=id_, rule_id="r", cls="business-logic", status=status,
                       severity=Severity.LOW, file="a.py", line=1, message="m",
                       runtime_dependent=rd)
    write_findings(ws, [f("A", True), f("B", False), f("C", True, FindingStatus.CONFIRMED)])
    assert promote_runtime_dependent(ws) == 1                       # only the raw+rd one
    by = {x.id: x.status for x in read_findings(ws)}
    assert by["A"] is FindingStatus.NEEDS_DEPLOYMENT_TESTING
    assert by["B"] is FindingStatus.RAW                             # not marked -> untouched
    assert by["C"] is FindingStatus.CONFIRMED                       # already terminal -> untouched
