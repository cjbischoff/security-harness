"""Tests for the red-team static->runtime bridge phase."""

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.redteam import discriminate, render_plan, write_plan
from sec_harness.workspace import Workspace, write_findings


def _f(fid, status=FindingStatus.CONFIRMED, risk=8, disposition=None, runtime_test=None):
    return Finding(
        id=fid, rule_id="r", cls="authz", status=status, severity=Severity.HIGH,
        file="app/x.py", line=10, message=f"{fid} msg", risk_score=risk,
        runtime_disposition=disposition, runtime_test=runtime_test,
        evidence_sources=["semgrep:rule"],
    )


def test_discriminate_partitions():
    findings = [
        _f("A", disposition="needs-runtime", risk=9),                    # -> plan
        _f("B", disposition="static-settled", risk=9),                   # -> static
        _f("C", disposition="needs-runtime", risk=3),                    # -> below bar
        _f("D", status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, risk=8),  # -> plan (ndt)
        _f("E", status=FindingStatus.REJECTED, risk=9),                  # ignored
    ]
    d = discriminate(findings, min_risk=7)
    assert [f.id for f in d["needs_runtime"]] == ["A", "D"]
    assert [f.id for f in d["static_settled"]] == ["B"]
    assert [f.id for f in d["below_bar"]] == ["C"]


def test_discriminate_default_disposition_is_static():
    # A confirmed finding with no disposition set is treated as static-settled.
    d = discriminate([_f("A", disposition=None)], min_risk=7)
    assert [f.id for f in d["static_settled"]] == ["A"]
    assert not d["needs_runtime"]


def test_render_plan_sections_and_payload():
    rt = {"objective": "bypass authz", "preconditions": "valid low-priv token",
          "payloads": ["curl $HOST/admin -H \"Authorization: $TOKEN\""],
          "expected_signal": "200 instead of 403", "telemetry": "gateway access logs"}
    d = discriminate([_f("A", disposition="needs-runtime", risk=9, runtime_test=rt)], min_risk=7)
    md = render_plan(d, min_risk=7)
    for section in ("## Prioritization", "## Manual test directives",
                    "## Runtime-validation gaps", "## Static-settled"):
        assert section in md
    assert "curl $HOST/admin" in md and "bypass authz" in md


def test_render_plan_empty():
    d = discriminate([_f("A", disposition="static-settled")], min_risk=7)
    md = render_plan(d, min_risk=7)
    assert "No confirmed finding requires runtime validation" in md


def test_write_plan(tmp_path):
    ws = Workspace(tmp_path)
    ws.ensure()
    write_findings(ws, [_f("A", disposition="needs-runtime", risk=9)])
    result = write_plan(ws, min_risk=7)
    assert result["needs_runtime"] == 1
    assert (ws.reports / "redteam-plan.md").exists()
