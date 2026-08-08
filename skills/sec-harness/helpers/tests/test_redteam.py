"""Tests for the red-team static->runtime bridge phase."""

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.patch_status import PatchStatus
from sec_harness.phase_gate import write_gate_record
from sec_harness.redteam import (
    _above_bar,
    _fixed_patch_statuses,
    build_redteam_gate_record,
    discriminate,
    render_plan,
    write_plan,
)
from sec_harness.workspace import Workspace, write_findings


def _f(fid, status=FindingStatus.CONFIRMED, risk=8, disposition=None, runtime_test=None,
       severity=Severity.HIGH):
    return Finding(
        id=fid, rule_id="r", cls="authz", status=status, severity=severity,
        file="app/x.py", line=10, message=f"{fid} msg", risk_score=risk,
        runtime_disposition=disposition, runtime_test=runtime_test,
        evidence_sources=["semgrep:rule"],
    )


def test_above_bar_clears_prime_manual_test_regardless_of_risk():
    f = _f("P", risk=None, severity=Severity.LOW)
    f.history = [{"event": "redteam:prime-manual-test"}]
    assert _above_bar(f, min_risk=7) is True


def test_discriminate_partitions():
    findings = [
        _f("A", disposition="needs-runtime", risk=9),                    # -> plan
        _f("B", disposition="static-settled", risk=9),                   # -> static
        # low severity + below-bar risk -> below_bar (high/medium/critical are always actionable)
        _f("C", disposition="needs-runtime", risk=3, severity=Severity.LOW),
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


def test_static_settled_footer_counts_static_not_runtime_subset():
    # Regression: the footer must report the static_settled count, not the needs-runtime
    # code-settled subset (a rebind of `settled` inside the plan block clobbered the count).
    plan_f = _f("P", disposition="needs-runtime", risk=9)
    plan_f.dataflow = ["a -> b"]
    plan_f.preconditions = ["needs deploy"]
    findings = [
        plan_f,
        _f("S1", disposition="static-settled", risk=9),
        _f("S2", disposition="static-settled", risk=8),
    ]
    d = discriminate(findings, min_risk=7)
    md = render_plan(d, min_risk=7)
    assert "2 confirmed finding(s) are source-provable" in md   # S1+S2, not the 1 runtime item


def test_write_plan(tmp_path):
    ws = Workspace(tmp_path)
    ws.ensure()
    write_findings(ws, [_f("A", disposition="needs-runtime", risk=9)])
    result = write_plan(ws, min_risk=7)
    assert result["needs_runtime"] == 1
    assert (ws.reports / "redteam-plan.md").exists()


def test_write_plan_records_stage(tmp_path):
    from sec_harness.state import load_state

    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f("A", disposition="needs-runtime", risk=9)])
    write_plan(ws, min_risk=7)
    assert "redteam" in load_state(ws).stages


def _fixed(fid, patch_diff="--- a/x\n+++ b/x\n"):
    return Finding(id=fid, rule_id="r", cls="sqli", status=FindingStatus.FIXED,
                   severity=Severity.HIGH, file="app/x.py", line=10, message="m",
                   patch_diff=patch_diff, evidence_sources=["semgrep:rule"])


def test_fixed_patch_statuses_only_checks_fixed_with_patch(monkeypatch):
    import sec_harness.redteam as R

    monkeypatch.setattr(R, "check_patch_applied", lambda target, diff: PatchStatus.APPLIED)
    confirmed = _f("B", disposition="static-settled")  # not FIXED -> skipped
    no_patch = _fixed("C", patch_diff="")               # FIXED but no patch -> skipped
    fixed = _fixed("D")
    out = _fixed_patch_statuses([confirmed, no_patch, fixed], "/tgt")
    assert out == {"D": PatchStatus.APPLIED}


def test_render_plan_shows_caution_for_not_applied_fixed_finding():
    rt = {"objective": "confirm sqli patched", "payloads": ["curl $HOST"]}
    f = _fixed("D")
    f.runtime_test = rt
    f.risk_score = 9
    f.runtime_disposition = "needs-runtime"
    d = discriminate([f], min_risk=7)
    md = render_plan(d, min_risk=7, patch_statuses={"D": PatchStatus.NOT_APPLIED})
    assert "Caution" in md and "NOT been confirmed applied" in md


def test_render_plan_omits_caution_for_applied_fixed_finding():
    f = _fixed("D")
    f.runtime_test = {"objective": "confirm sqli patched"}
    f.risk_score = 9
    f.runtime_disposition = "needs-runtime"
    d = discriminate([f], min_risk=7)
    md = render_plan(d, min_risk=7, patch_statuses={"D": PatchStatus.APPLIED})
    assert "Caution" not in md


def test_write_plan_with_target_annotates_caution(monkeypatch, tmp_path):
    import sec_harness.redteam as R

    monkeypatch.setattr(R, "check_patch_applied", lambda target, diff: PatchStatus.NOT_APPLIED)
    ws = Workspace(tmp_path); ws.ensure()
    f = _fixed("D")
    f.runtime_test = {"objective": "confirm sqli patched"}
    f.risk_score = 9
    f.runtime_disposition = "needs-runtime"
    write_findings(ws, [f])
    write_plan(ws, min_risk=7, target="/tgt")
    md = (ws.reports / "redteam-plan.md").read_text()
    assert "Caution" in md


def _rt(id_, sev, risk, disp="needs-runtime", status=None, evidence_sources=None):
    return Finding(id=id_, rule_id="r", cls="authz",
                   status=status or FindingStatus.CONFIRMED, severity=sev,
                   file="a.py", line=1, message="m", risk_score=risk,
                   runtime_disposition=disp,
                   evidence_sources=evidence_sources if evidence_sources is not None else [])


def test_confirmed_high_severity_needs_runtime_is_actionable_below_min_risk():
    # critical needs-runtime with risk 5 (below the 7 bar) MUST still be a directive (O-016/O-031).
    # A real confirmed finding always carries a tool receipt via the confirmation gate.
    crit = _rt("A-1", Severity.CRITICAL, 5, evidence_sources=["ast-grep:sink"])
    disc = discriminate([crit], min_risk=7)
    assert [f.id for f in disc["needs_runtime"]] == ["A-1"]
    assert disc["below_bar"] == []


def test_low_severity_needs_runtime_gated_by_min_risk():
    low = _rt("A-2", Severity.LOW, 4, evidence_sources=["ast-grep:sink"])
    disc = discriminate([low], min_risk=7)
    assert [f.id for f in disc["below_bar"]] == ["A-2"]
    assert disc["needs_runtime"] == []


def test_lead_carrier_without_receipt_is_not_a_directive():
    # LEAD/doc-lead carriers (llm-claimed-only, no tool receipt) must not bypass min_risk via
    # the severity gate, even at MEDIUM+needs-deployment-testing.
    lead = _rt(
        "A-3", Severity.MEDIUM, None,
        status=FindingStatus.NEEDS_DEPLOYMENT_TESTING,
        evidence_sources=["llm-claimed:doc-lead"],
    )
    disc = discriminate([lead], min_risk=7)
    assert [f.id for f in disc["below_bar"]] == ["A-3"]
    assert disc["needs_runtime"] == []


def test_build_redteam_gate_record_from_needs_runtime_finding(tmp_path):
    f = _rt("A-6", Severity.HIGH, 8, evidence_sources=["ast-grep:sink"])
    rec = build_redteam_gate_record([f], verdicts={"A-6": "WEAKENED"})
    assert rec["phase"] == "redteam"
    assert rec["claims"]["A-6"]["refs"] == [f"{f.file}:{f.line}"]
    assert rec["survivors"] == ["A-6"]  # WEAKENED, not INVALIDATED -> survives
    ws = Workspace(tmp_path)
    ws.ensure()
    path = write_gate_record(ws, "redteam", rec)
    assert path.name == "redteam.json"


def test_needs_runtime_sorts_critical_before_low_when_risk_score_is_none():
    # Promoted NDT/LEAD findings often have no risk_score; severity must tiebreak the sort.
    # Both need a tool receipt + actionable severity to enter the plan without a risk_score.
    medium = _rt("A-4", Severity.MEDIUM, None, evidence_sources=["ast-grep:sink"])
    crit = _rt("A-5", Severity.CRITICAL, None, evidence_sources=["ast-grep:sink"])
    disc = discriminate([medium, crit], min_risk=7)
    assert [f.id for f in disc["needs_runtime"]] == ["A-5", "A-4"]


def test_directive_renders_markdown_not_repr():
    from sec_harness.redteam import _directive_block

    f = _f("investigation:authz", status=FindingStatus.NEEDS_DEPLOYMENT_TESTING,
           runtime_test={
               "objective": "verify CE-ID isolation",
               "preconditions": ["Two distinct TaaS CEs (CE-A, CE-B)", "low-priv user in CE-A"],
               "expected_signal": {"secure": "403 forbidden", "insecure": "201 + record"},
               "telemetry": ["service access logs", "audit log"],
           })
    out = _directive_block(f)
    assert "['" not in out and "{'" not in out          # no python repr
    assert "\n  - Two distinct TaaS CEs (CE-A, CE-B)" in out   # precondition bullet
    assert "**secure:**" in out and "403 forbidden" in out     # labeled signal
    assert "**insecure:**" in out and "201 + record" in out
    assert "\n  - service access logs" in out                  # telemetry bullet


def test_directive_renders_string_typed_fields_verbatim():
    # runtime_test fields aren't schema-forced to lists/dicts; a plain string must render,
    # not collapse to "_not specified_" (regression guard for the str branch).
    from sec_harness.redteam import _directive_block

    f = _f("investigation:authz", status=FindingStatus.NEEDS_DEPLOYMENT_TESTING,
           runtime_test={
               "objective": "verify CE-ID isolation",
               "preconditions": "valid low-priv token",
               "expected_signal": "200 instead of 403",
           })
    out = _directive_block(f)
    assert "valid low-priv token" in out          # string precondition, verbatim
    assert "200 instead of 403" in out            # string expected_signal, verbatim
    assert "_not specified_" not in out.split("**Telemetry")[0]  # str fields not collapsed
