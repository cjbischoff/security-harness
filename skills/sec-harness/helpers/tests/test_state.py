"""Tests for workspace layout + finding persistence + campaign state."""

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, read_findings, write_findings


def _f(id_):
    return Finding(id=id_, rule_id="r", cls="sqli", status=FindingStatus.CANDIDATE,
                   severity=Severity.HIGH, file="a.py", line=1, message="m")


def test_workspace_ensure_creates_dirs(tmp_path):
    ws = Workspace(tmp_path / "workspace")
    ws.ensure()
    assert ws.findings_dir.is_dir()
    assert ws.kb.is_dir()


def test_findings_roundtrip(tmp_path):
    ws = Workspace(tmp_path / "workspace")
    ws.ensure()
    write_findings(ws, [_f("F-0002"), _f("F-0001")])
    out = read_findings(ws)
    assert [f.id for f in out] == ["F-0001", "F-0002"]


def test_load_state_defaults_to_pass_one(tmp_path):
    from sec_harness.state import load_state
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    st = load_state(ws)
    assert st.pass_number == 1 and st.active_sha is None


def test_begin_pass_increments_after_completed_pass(tmp_path):
    from sec_harness.state import begin_pass, save_state
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    st = begin_pass(ws, "sha1")
    assert st.pass_number == 1
    st.stages["prefilter"] = "done"; save_state(ws, st)
    st2 = begin_pass(ws, "sha2")
    assert st2.pass_number == 2 and st2.active_sha == "sha2" and st2.stages == {}
