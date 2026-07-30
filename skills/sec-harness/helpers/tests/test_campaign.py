"""Tests for campaign pass lifecycle."""

from sec_harness.campaign import pass_report, record_stage
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.state import begin_pass, load_state
from sec_harness.workspace import Workspace, write_findings


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
