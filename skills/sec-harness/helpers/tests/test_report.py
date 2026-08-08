"""Tests for Markdown reporting."""

import json
from pathlib import Path

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.patch_status import PatchStatus
from sec_harness.report import render_finding, select_reportable, to_markdown, write_report
from sec_harness.workspace import Workspace, write_findings


def _f_new(fid, status, cls="authz", sev=Severity.MEDIUM):
    """Build a minimal Finding for Task-2 integration tests."""
    return Finding(id=fid, rule_id="r", cls=cls, status=status, severity=sev,
                   file="a.py", line=1, message="m", evidence_sources=["semgrep:x"])


def _profile(ws: Workspace, attack_surface: list) -> None:
    """Write a minimal scan-profile.json so build_coverage_ledger can run."""
    ws.kb.mkdir(parents=True, exist_ok=True)
    (ws.kb / "scan-profile.json").write_text(json.dumps({
        "languages": [], "frameworks": [], "entrypoints": [], "runnable": False,
        "attack_surface": attack_surface, "sast_plan": {}, "agents_to_spawn": attack_surface,
        "budget_hint": {}}))


def test_findings_json_includes_ndt(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure(); _profile(ws, ["authz"])
    write_findings(ws, [_f_new("C-1", FindingStatus.CONFIRMED),
                        _f_new("N-1", FindingStatus.NEEDS_DEPLOYMENT_TESTING)])
    write_report(ws)
    ids = {f["id"]: f["status"] for f in json.loads(ws.findings_json_path.read_text())}
    assert ids["C-1"] == "confirmed"
    assert ids["N-1"] == "needs-deployment-testing"  # NDT now present


def test_report_auto_builds_coverage_ledger_and_shows_gap(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure(); _profile(ws, ["authz", "sqli"])
    write_findings(ws, [_f_new("C-1", FindingStatus.CONFIRMED, cls="authz")])  # sqli uncovered
    write_report(ws)
    assert (ws.kb / "coverage-ledger.json").exists()
    assert "Coverage completeness" in ws.report_path.read_text()
    assert json.loads((ws.kb / "coverage-ledger.json").read_text())["completeness"] == "partial"


def _f(id_, sev, cls="sqli"):
    return Finding(id=id_, rule_id="r", cls=cls, status=FindingStatus.CONFIRMED,
                   severity=sev, file="app.py", line=18, message="msg")


def test_markdown_contains_table_and_counts():
    # Intent: both findings appear, location shown, severity present.
    md = to_markdown([_f("F-0001", Severity.HIGH), _f("F-0002", Severity.LOW)])
    assert "app.py:18" in md
    assert "F-0001" in md and "F-0002" in md
    assert "high" in md.lower()


def test_markdown_orders_by_severity_desc():
    # Intent: higher-risk / higher-severity finding appears first in output.
    # Critical (risk higher) must precede Low in the triage table.
    md = to_markdown([_f("F-0001", Severity.LOW), _f("F-0002", Severity.CRITICAL)])
    assert md.index("F-0002") < md.index("F-0001")


def test_markdown_includes_token_spend_when_given():
    md = to_markdown([_f("F-0001", Severity.HIGH)], token_spend={"investigate": 1200})
    assert "Token spend" in md and "investigate" in md and "1200" in md


def _rf(id_, status, risk=None, verification=None, sev=Severity.HIGH):
    return Finding(id=id_, rule_id="r", cls="sqli", status=status, severity=sev,
                   file="app.py", line=18, message="m", risk_score=risk,
                   verification=verification)


def test_to_markdown_shows_risk_and_verification():
    # Intent: risk score and verification text both appear in the report.
    # Risk appears in the triage table header; verification in the detailed section.
    md = to_markdown([_rf("F-0002", FindingStatus.FIXED, risk=9, verification="verified-static")])
    assert "Risk" in md
    assert "| 9 |" in md          # Risk column in the triage table
    assert "verified-static" in md


def test_select_reportable_filters_and_sorts():
    findings = [
        _rf("F-0001", FindingStatus.CONFIRMED, risk=5),
        _rf("F-0002", FindingStatus.FIXED, risk=9),
        _rf("F-0003", FindingStatus.REJECTED, risk=8),
        _rf("F-0004", FindingStatus.CANDIDATE),
    ]
    out = select_reportable(findings)
    assert [f.id for f in out] == ["F-0002", "F-0001"]  # rejected/candidate dropped; risk-sorted


def test_report_renders_coverage_section(tmp_path):
    import json

    from sec_harness.workspace import Workspace

    ws = Workspace(tmp_path / "ws"); ws.ensure()
    (ws.kb / "coverage.json").write_text(json.dumps({
        "languages": [{"language": "liquid", "files": 194, "tier": "none"},
                      {"language": "javascript", "files": 40, "tier": "dataflow"}],
        "dataflow_pct": 17, "uncovered": ["liquid"]}))
    write_report(ws)
    md = ws.report_path.read_text()
    assert "Coverage" in md and "liquid" in md and "17%" in md


def test_write_report_writes_final_artifacts(tmp_path):
    import json

    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [
        _rf("F-0002", FindingStatus.FIXED, risk=9, verification="verified-static"),
        _rf("F-0009", FindingStatus.REJECTED, risk=1),
    ])
    result = write_report(ws)
    assert result["reported"] == 1
    assert ws.sarif_path.exists() and ws.report_path.exists()
    sarif = json.loads(ws.sarif_path.read_text())
    assert len(sarif["runs"][0]["results"]) == 1        # only the reportable finding
    assert "verified-static" in ws.report_path.read_text()
    assert ws.findings_json_path.exists()
    fj = json.loads(ws.findings_json_path.read_text())
    assert len(fj) == 1 and fj[0]["id"] == "F-0002"


def _tf(id_, sev, **kw):
    from sec_harness.models import Finding, FindingStatus, Severity
    d = {"id": id_, "rule_id": "r", "cls": "xss", "status": FindingStatus.CONFIRMED,
         "severity": Severity(sev), "file": "a.js", "line": 5, "message": "msg",
         "dataflow": ["src @ a.js:1", "-> sink @ a.js:5"], "evidence": "innerHTML=x",
         "evidence_sources": ["ast-grep:sink", "llm-claimed:reach"], "cvss_vector": "CVSS:3.1/AV:N",
         "risk_score": 7}
    d.update(kw)
    return Finding(**d)


def test_render_finding_full_for_high():
    from sec_harness.report import render_finding
    md = render_finding(_tf("XSS-1", "high"))
    for sec in ("1. Summary", "2. Mechanism", "3. Confirmation", "4. Impact",
                "5. Severity", "6. Confirmed Attack", "7. Fix", "8. Testing"):
        assert sec in md
    assert "ast-grep:sink" in md          # tool receipt surfaced
    assert "llm-claimed:reach" in md      # claimed surfaced separately
    assert "src @ a.js:1" in md           # dataflow rendered


def test_render_finding_condensed_for_medium():
    from sec_harness.report import render_finding
    md = render_finding(_tf("XSS-2", "medium"))
    for sec in ("1. Summary", "2. Mechanism", "3. Severity", "4. Fix"):
        assert sec in md
    for sec in ("5. Severity", "7. Fix", "3. Confirmation", "4. Impact", "6. Confirmed Attack", "8. Testing"):
        assert sec not in md              # condensed omits these (1-4 now; no 5,7)


def test_render_finding_flags_missing_receipt():
    from sec_harness.report import render_finding
    md = render_finding(_tf("X-3", "high", evidence_sources=["llm-claimed:only"]))
    assert "NONE" in md and "not confirmable" in md


def test_to_markdown_includes_detailed_section():
    # Intent: confirmed finding detail block appears under the "Confirmed" heading.
    from sec_harness.report import to_markdown
    md = to_markdown([_tf("XSS-1", "high")])
    assert "## Confirmed" in md and "### XSS-1" in md


def test_report_sections_needs_deployment(tmp_path):
    # Intent: NDT findings appear in the report and are NOT counted as confirmed/reported.
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.report import to_markdown, write_report
    from sec_harness.workspace import Workspace, write_findings
    ndt = Finding(id="N1", rule_id="r", cls="ssrf", status=FindingStatus.NEEDS_DEPLOYMENT_TESTING,
                  severity=Severity.HIGH, file="a.py", line=3, message="needs proxy to confirm")
    md = to_markdown([], needs_deployment=[ndt])
    # New structure: NDT appears under "Needs runtime proof" heading; "N1" present
    assert "Needs runtime proof" in md and "N1" in md
    # write_report picks NDT from the workspace and does NOT count it as reported
    ws = Workspace(tmp_path); ws.ensure(); write_findings(ws, [ndt])
    res = write_report(ws)
    assert res["reported"] == 0
    assert "Needs runtime proof" in ws.report_path.read_text()


def test_needs_deployment_split_by_dataflow_presence(tmp_path):
    # Intent: both NDT findings appear in the report; both appear in the triage table
    # and in the "Needs runtime proof" section. The old split-by-dataflow sub-headings
    # are gone; triage ordering (risk-desc then id) determines row order.
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.report import to_markdown
    settled = Finding(id="A", rule_id="r", cls="sqli",
                      status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.HIGH,
                      file="a.py", line=1, message="m", dataflow=["src", "sink"],
                      preconditions=["auth"])
    incomplete = Finding(id="B", rule_id="r", cls="sqli",
                         status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.HIGH,
                         file="b.py", line=1, message="m", verification="verify-error")
    md = to_markdown([], needs_deployment=[settled, incomplete])
    assert "Needs runtime proof" in md
    assert "A" in md and "B" in md
    # Both appear in triage; equal risk → alphabetical, so A before B
    triage = md.split("## Triage")[1].split("##")[0]
    assert triage.index("| A") < triage.index("| B")


def test_report_links_redteam_plan_and_shows_receipts(tmp_path):
    # Intent: report links redteam-plan.md (T11a) and shows tool receipts (T11b).
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    (ws.reports).mkdir(parents=True, exist_ok=True)
    (ws.reports / "redteam-plan.md").write_text("# plan\n")
    write_findings(ws, [Finding(id="F-1", rule_id="r", cls="authz", status=FindingStatus.CONFIRMED,
                                severity=Severity.MEDIUM, file="a.py", line=1, message="m",
                                risk_score=5, evidence_sources=["ripgrep:a.py:1"])])
    write_report(ws)
    md = (ws.reports / "report.md").read_text()
    assert "redteam-plan.md" in md            # T11a: link the manual test plan
    assert "ripgrep:a.py:1" in md             # T11b: receipts visible even in condensed (medium) tier


def test_to_markdown_renders_coverage_ledger():
    from sec_harness.report import to_markdown
    led = {"completeness": "partial", "surfaces": [{"id": "auth", "disposition": "reported"}],
           "deferred": ["liquid templates"]}
    md = to_markdown([], coverage_ledger=led)
    assert "Coverage completeness" in md and "liquid templates" in md


def test_write_report_records_stage(tmp_path):
    from sec_harness.state import load_state

    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_rf("F-0002", FindingStatus.FIXED, risk=9, verification="verified-static")])
    write_report(ws)
    assert "report" in load_state(ws).stages


def _fixed_with_patch(fid, patch_diff="--- a/x\n+++ b/x\n"):
    return Finding(id=fid, rule_id="r", cls="sqli", status=FindingStatus.FIXED,
                   severity=Severity.HIGH, file="app.py", line=18, message="m",
                   patch_diff=patch_diff, risk_score=9)


def test_render_finding_shows_caution_when_patch_not_applied():
    md = render_finding(_fixed_with_patch("F-1"), patch_status=PatchStatus.NOT_APPLIED)
    assert "Caution" in md and "NOT been confirmed applied" in md


def test_render_finding_omits_caution_when_patch_applied():
    md = render_finding(_fixed_with_patch("F-1"), patch_status=PatchStatus.APPLIED)
    assert "Caution" not in md


def test_render_finding_omits_caution_when_patch_status_not_given():
    md = render_finding(_fixed_with_patch("F-1"))
    assert "Caution" not in md


def test_write_report_with_target_annotates_caution(monkeypatch, tmp_path):
    import sec_harness.report as Rp

    monkeypatch.setattr(Rp, "check_patch_applied", lambda target, diff: PatchStatus.NOT_APPLIED)
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_fixed_with_patch("F-1")])
    write_report(ws, target="/tgt")
    md = ws.report_path.read_text()
    assert "Caution" in md


def test_write_report_without_target_skips_patch_check(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_fixed_with_patch("F-1")])
    write_report(ws)
    md = ws.report_path.read_text()
    assert "Caution" not in md


def test_write_report_renders_token_spend(tmp_path):
    from sec_harness import cost
    from sec_harness.report import write_report
    from sec_harness.state import load_state, save_state
    from sec_harness.workspace import Workspace, write_findings
    ws = Workspace(root=tmp_path / "ws"); ws.ensure()
    write_findings(ws, [])
    st = load_state(ws)
    cost.record_agent(st, "investigate", "sonnet", 1234)
    save_state(ws, st)
    write_report(ws)
    assert "Token spend by phase" in ws.report_path.read_text()
    assert "1234" in ws.report_path.read_text()


def _dep():
    return Finding(id="DEP-1", rule_id="osv:GHSA-x", cls="deps",
                   status=FindingStatus.CONFIRMED, severity=Severity.LOW,
                   file="package-lock.json", line=1,
                   message="decompress@4.2.1: GHSA-x — archive path traversal",
                   evidence="decompress@4.2.1", evidence_sources=["sca:osv:GHSA-x"],
                   reachability={"reachable": False, "blocker": "dev-build-only"})


def _code_low():
    return Finding(id="CODE-1", rule_id="r", cls="authz",
                   status=FindingStatus.CONFIRMED, severity=Severity.LOW,
                   file="a.js", line=9, message="thing",
                   dataflow=["src -> sink"])


def test_dep_view_has_no_hollow_slots():
    from sec_harness.report import render_finding
    out = render_finding(_dep())
    assert "(no dataflow recorded)" not in out
    assert "(no vector)" not in out
    assert "(no patch generated" not in out
    assert "decompress@4.2.1" in out
    assert "reachable" in out.lower() and "dev-build-only" in out
    assert "GHSA-x" in out


def test_condensed_tier_renumbers_without_gaps():
    from sec_harness.report import render_finding
    out = render_finding(_code_low())
    assert "**1. Summary" in out and "**2. Mechanism" in out
    assert "**3. Severity" in out and "**4. Fix" in out
    assert "**5. " not in out and "**7. " not in out


def test_dep_view_shows_caution_when_patch_not_applied():
    from sec_harness.report import render_finding
    dep = Finding(id="DEP-2", rule_id="osv:GHSA-y", cls="deps",
                  status=FindingStatus.FIXED, severity=Severity.LOW,
                  file="package-lock.json", line=1, message="pkg@1.0: GHSA-y",
                  evidence="pkg@1.0", patch_diff="--- a/x\n+++ b/x\n")
    md = render_finding(dep, patch_status=PatchStatus.NOT_APPLIED)
    assert "Caution" in md and "NOT been confirmed applied" in md


def _ndt():
    return Finding(rule_id="investigation:authz", cls="authz",
                   status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.MEDIUM,
                   file="src/rbac/spec.js", line=133, risk_score=5,
                   message="sole unrestrictedInTaas write; cross-CE injection if Go handler unscoped",
                   dataflow=["privilege(unrestrictedInTaas) @ spec.js:133", "-> Go handler UNVERIFIED"],
                   preconditions=["Go handler does not enforce per-CE isolation"],
                   runtime_test={"objective": "verify CE-ID isolation on operatorFeedbackWrite",
                                 "expected_signal": {"secure": "403", "insecure": "201 + CE-B record"}},
                   id="N-1")


def test_render_ndt_labels_needs_runtime_and_shows_test():
    from sec_harness.report import render_ndt
    out = render_ndt(_ndt())
    header = out.splitlines()[0]
    assert "needs runtime" in header.lower()              # view labels it needs-runtime
    assert "confirmed" not in header.lower()              # view's own heading never says confirmed
    assert "spec.js:133" in out
    assert "verify CE-ID isolation" in out                # the test objective
    assert "403" in out and "201 + CE-B record" in out    # secure/insecure signal
    assert "redteam-plan.md" in out                       # pointer to the runnable test


def test_render_ndt_degrades_without_runtime_test():
    import dataclasses

    from sec_harness.report import render_ndt
    f = dataclasses.replace(_ndt(), runtime_test=None, dataflow=[], preconditions=[])
    out = render_ndt(f)
    assert "needs runtime" in out.lower()
    assert "no source chain recorded" in out
    assert "none recorded" in out
    assert "redteam-plan.md" in out                       # pointer present unconditionally


# ── Task-4 new tests: bottom-line counts + triage ordering ────────────────────

def _confirmed_dep():
    """Low-risk confirmed dep finding for T4 fixtures."""
    return Finding(rule_id="osv:GHSA-x", cls="deps", status=FindingStatus.CONFIRMED,
                   severity=Severity.LOW, file="package-lock.json", line=1, risk_score=3,
                   message="decompress@4.2.1: GHSA-x — path traversal", evidence="decompress@4.2.1",
                   evidence_sources=["sca:osv:GHSA-x"], reachability={"reachable": False, "blocker": "dev"},
                   id="DEP-T4")


def _ndt_med():
    """Medium-risk NDT authz finding for T4 fixtures."""
    return Finding(rule_id="investigation:authz", cls="authz",
                   status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.MEDIUM,
                   file="src/rbac/spec.js", line=133, risk_score=5, message="cross-CE write lead",
                   dataflow=["a -> b"], preconditions=["handler unscoped"],
                   runtime_test={"objective": "verify isolation",
                                 "expected_signal": {"secure": "403", "insecure": "201"}},
                   id="NDT-T4")


def test_to_markdown_bottom_line_counts_ndt_separately():
    """NDT findings must appear in 'Needs runtime proof' count, never in confirmed counts."""
    out = to_markdown([_confirmed_dep()], needs_deployment=[_ndt_med()])
    assert "Needs runtime proof: 1" in out                 # NDT counted, not hidden
    # confirmed count line must not include the NDT medium finding
    conf_line = next(l for l in out.splitlines() if l.startswith("Confirmed:"))
    # confirmed = 0 crit/high/med, 1 low; NDT medium NOT folded into the medium bucket
    assert "0/0/0/1" in conf_line


def test_triage_puts_ndt_lead_above_low_dep():
    """Higher-risk NDT row sorts above lower-risk dep in triage; NDT section before Confirmed."""
    out = to_markdown([_confirmed_dep()], needs_deployment=[_ndt_med()])
    triage = out.split("## Triage")[1].split("##")[0]
    # NDT-T4 (risk 5) above DEP-T4 (risk 3) in the triage table
    assert triage.index("NDT-T4") < triage.index("DEP-T4")
    assert "## Needs runtime proof" in out
    assert out.index("## Needs runtime proof") < out.index("## Confirmed")   # leads above confirmed


def test_triage_dep_row_preserves_semver_and_advisory():
    """`what` clip splits on period-space, so `decompress@4.2.1` isn't truncated to `decompress@4`."""
    out = to_markdown([_confirmed_dep()])
    triage = out.split("## Triage")[1].split("##")[0]
    dep_row = next(l for l in triage.splitlines() if "DEP-T4" in l)
    assert "decompress@4.2.1" in dep_row       # semver intact
    assert "decompress@4 " not in dep_row      # not clipped at the first bare dot
