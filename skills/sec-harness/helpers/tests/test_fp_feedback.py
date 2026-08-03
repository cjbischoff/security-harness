from sec_harness.fp_feedback import render_fp_feedback
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, write_findings


def _rej(fid, msg, reason, line=3):
    f = Finding(id=fid, rule_id="r", cls="ssrf", status=FindingStatus.REJECTED,
                severity=Severity.MEDIUM, file="a.py", line=line, message=msg)
    f.history.append({"event": "validate:rejected", "reason": reason})
    return f


def test_render_fp_feedback_lists_rejected_reasons(tmp_path):
    ws = Workspace(root=tmp_path / "ws"); ws.ensure()
    write_findings(ws, [_rej("F-1", "url built from const", "destination not attacker-controlled")])
    block = render_fp_feedback(ws)
    assert "ssrf" in block
    assert "destination not attacker-controlled" in block
    assert "<untrusted" in block           # envelope-wrapped


def test_render_fp_feedback_empty_when_no_rejects(tmp_path):
    ws = Workspace(root=tmp_path / "ws"); ws.ensure()
    write_findings(ws, [])
    assert render_fp_feedback(ws) == ""


def test_render_fp_feedback_honors_cap(tmp_path):
    ws = Workspace(root=tmp_path / "ws"); ws.ensure()
    write_findings(ws, [_rej(f"F-{i}", f"m{i}", f"reason {i}", line=i) for i in range(60)])
    block = render_fp_feedback(ws, cap=5)
    assert block.count("- class=") == 5
