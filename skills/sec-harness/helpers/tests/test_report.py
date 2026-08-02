"""Tests for Markdown reporting."""

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.report import select_reportable, to_markdown, write_report
from sec_harness.workspace import Workspace, write_findings


def _f(id_, sev, cls="sqli"):
    return Finding(id=id_, rule_id="r", cls=cls, status=FindingStatus.CONFIRMED,
                   severity=sev, file="app.py", line=18, message="msg")


def test_markdown_contains_table_and_counts():
    md = to_markdown([_f("F-0001", Severity.HIGH), _f("F-0002", Severity.LOW)])
    assert "app.py:18" in md
    assert "F-0001" in md and "F-0002" in md
    assert "high" in md.lower()


def test_markdown_orders_by_severity_desc():
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
    md = to_markdown([_rf("F-0002", FindingStatus.FIXED, risk=9, verification="verified-static")])
    assert "Risk" in md and "Verification" in md
    assert "| 9 |" in md
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
    for sec in ("1. Summary", "2. Mechanism", "5. Severity", "7. Fix"):
        assert sec in md
    for sec in ("3. Confirmation", "4. Impact", "6. Confirmed Attack", "8. Testing"):
        assert sec not in md              # condensed omits these


def test_render_finding_flags_missing_receipt():
    from sec_harness.report import render_finding
    md = render_finding(_tf("X-3", "high", evidence_sources=["llm-claimed:only"]))
    assert "NONE" in md and "not confirmable" in md


def test_to_markdown_includes_detailed_section():
    from sec_harness.report import to_markdown
    md = to_markdown([_tf("XSS-1", "high")])
    assert "## Detailed findings" in md and "### XSS-1" in md


def test_report_sections_needs_deployment(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.report import to_markdown, write_report
    from sec_harness.workspace import Workspace, write_findings
    ndt = Finding(id="N1", rule_id="r", cls="ssrf", status=FindingStatus.NEEDS_DEPLOYMENT_TESTING,
                  severity=Severity.HIGH, file="a.py", line=3, message="needs proxy to confirm")
    md = to_markdown([], needs_deployment=[ndt])
    assert "Needs deployment testing" in md and "N1" in md
    # write_report picks NDT from the workspace and does NOT count it as reported
    ws = Workspace(tmp_path); ws.ensure(); write_findings(ws, [ndt])
    res = write_report(ws)
    assert res["reported"] == 0
    assert "Needs deployment testing" in ws.report_path.read_text()


def test_report_links_redteam_plan_and_shows_receipts(tmp_path):
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
