"""Tests for postflight durable context (C2)."""
import json

from sec_harness.context import prior_context_path
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.postflight import build_prior_context, run_postflight
from sec_harness.workspace import Workspace, write_findings


def _f(id_, status, cls="crypto", file="a.py", line=5, fp=None, history=None):
    return Finding(id=id_, rule_id="r", cls=cls, status=status, severity=Severity.HIGH,
                   file=file, line=line, message="m", fingerprint=fp or id_, history=history or [])


def test_build_prior_context_captures_confirmed_and_rejected(tmp_path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [
        _f("A", FindingStatus.CONFIRMED),
        _f("B", FindingStatus.REJECTED, history=[{"event": "critic:rejected", "reason": "dead code"}]),
        _f("C", FindingStatus.CANDIDATE),
    ])
    c = build_prior_context(ws, "sha1")
    kinds = {i.kind for i in c.items}
    assert "prior_finding" in kinds and "note" in kinds
    assert all(i.trust == "prior-scan" for i in c.items)
    rej = [i for i in c.items if i.kind == "note"][0]
    assert "dead code" in rej.text and "do not re-litigate" in rej.text
    assert len(c.items) == 2   # candidate excluded


def test_run_postflight_merges_and_drifts(tmp_path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f("A", FindingStatus.CONFIRMED, file="keep.py"),
                        _f("B", FindingStatus.REJECTED, file="changed.py",
                           history=[{"event": "validate:rejected", "reason": "mitigated"}])])
    assert run_postflight(ws, "sha1") == 2
    # second pass: 'changed.py' re-examined this scan (finding B gone from workspace);
    # drift drops the stale changed.py conclusion, keep.py (A) persists.
    (ws.findings_dir / "B.json").unlink()
    run_postflight(ws, "sha2", changed_files={"changed.py"})
    data = json.loads(prior_context_path(ws).read_text())
    wheres = [i["where"].split(":")[0] for i in data["items"]]
    assert "keep.py" in wheres and "changed.py" not in wheres


def test_run_postflight_records_stage(tmp_path):
    from sec_harness.state import load_state

    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f("A", FindingStatus.CONFIRMED)])
    run_postflight(ws, "sha1")
    assert "postflight" in load_state(ws).stages
