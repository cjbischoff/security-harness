"""Tests for deterministic risk calibration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sec_harness.calibrate import calibrate_findings, calibrate_score
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, read_findings, write_findings


def _f(id_, cls, sev, dataflow, status=FindingStatus.CONFIRMED):
    return Finding(id=id_, rule_id="r", cls=cls, status=status, severity=sev,
                   file="app.py", line=1, message="m", dataflow=dataflow)


def test_score_high_sqli_reachable():
    # high(7) + reachable(+1) + high-impact class(+1) = 9
    assert calibrate_score(_f("F-1", "sqli", Severity.HIGH, ["a @ x:1", "-> b @ x:2"])) == 9


def test_score_low_non_impact_no_dataflow():
    assert calibrate_score(_f("F-2", "xss", Severity.LOW, [])) == 3


def test_score_clamped_to_10():
    # critical(9) + reachable(+1) + impact(+1) = 11 -> clamp 10
    assert calibrate_score(_f("F-3", "cmdi", Severity.CRITICAL, ["a", "b", "c"])) == 10


def test_calibrate_findings_scores_only_confirmed(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [
        _f("F-1", "sqli", Severity.HIGH, ["a", "b"], status=FindingStatus.CONFIRMED),
        _f("F-2", "sqli", Severity.HIGH, ["a", "b"], status=FindingStatus.RAW),
    ])
    assert calibrate_findings(ws) == 1
    by_id = {f.id: f for f in read_findings(ws)}
    assert by_id["F-1"].risk_score == 9
    assert by_id["F-2"].risk_score is None  # not confirmed -> untouched


def test_calibrate_uses_cvss_vector_when_present():
    from sec_harness.models import Finding, FindingStatus, Severity
    f = Finding(id="F-1", rule_id="r", cls="sqli", status=FindingStatus.CONFIRMED,
                severity=Severity.LOW, file="a.py", line=1, message="m",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    # CVSS 9.8 wins over the LOW severity heuristic
    assert calibrate_score(f) == 10


def test_calibrate_malformed_vector_falls_back():
    from sec_harness.models import Finding, FindingStatus, Severity
    f = Finding(id="F-2", rule_id="r", cls="xss", status=FindingStatus.CONFIRMED,
                severity=Severity.LOW, file="a.py", line=1, message="m",
                dataflow=[], cvss_vector="garbage")
    assert calibrate_score(f) == 3   # existing low/no-dataflow/non-impact heuristic


def _crit(cvss, preconds):
    return Finding(id="F-P", rule_id="r", cls="sqli", status=FindingStatus.CONFIRMED,
                   severity=Severity.CRITICAL, file="a.py", line=1, message="m",
                   cvss_vector=cvss, preconditions=preconds)


def test_precondition_weight_ignores_free_preconditions():
    from sec_harness.calibrate import _precondition_weight
    # unauthenticated / no-config / public are NOT mitigants -> weight 0
    assert _precondition_weight(
        ["unauthenticated buyer reaching checkout", "no config required", "public endpoint"]
    ) == 0.0
    # a real barrier counts; "unauth" containing "auth" must not misclassify as weak
    assert _precondition_weight(["requires admin token"]) == 1.0
    assert _precondition_weight(["authenticated low-priv user"]) == 0.5


def test_precondition_weight_default_config_vs_non_default_config():
    from sec_harness.calibrate import _precondition_weight
    # "default config" (ships vulnerable out of the box) is a FREE substring of the STRONG
    # "non-default config" (requires a non-default setting) -- both directions must classify
    # correctly despite the substring collision.
    assert _precondition_weight(["default config"]) == 0.0
    assert _precondition_weight(["non-default config"]) == 1.0


def test_precondition_cap_uses_weight_not_count():
    from sec_harness.calibrate import _precondition_cap
    # three FREE preconditions -> weight 0 -> no cap (was: count 3 -> cap 5)
    assert _precondition_cap(["unauthenticated", "remote", "no setup"]) == 10
    # one strong barrier -> weight 1 -> cap 8
    assert _precondition_cap(["requires admin token"]) == 8
    # two strong -> weight 2 -> cap 7
    assert _precondition_cap(["requires admin token", "non-default config"]) == 7
    # three strong -> weight 3 -> cap 5
    assert _precondition_cap(["admin", "non-default config", "local access"]) == 5


def test_precondition_cap_lowers_score():
    crit_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 -> 10
    assert calibrate_score(_crit(crit_vec, [])) == 10                       # weight 0 -> no cap
    assert calibrate_score(_crit(crit_vec, ["unauthenticated"])) == 10      # free -> no cap
    strong_preconds = ["requires admin token", "non-default config", "local access"]
    assert calibrate_score(_crit(crit_vec, strong_preconds)) == 8  # weight 3 -> cap 5, floored 8


def _sev(id_, sev, cvss, preconds):
    from sec_harness.models import Finding, FindingStatus
    return Finding(id=id_, rule_id="r", cls="authz", status=FindingStatus.CONFIRMED,
                   severity=sev, file="a.py", line=1, message="m",
                   cvss_vector=cvss, preconditions=preconds)


def test_critical_never_ranks_below_medium():
    # O-031: NoSQL-ATO critical (3 free preconds) must outrank a committed-secret medium.
    from sec_harness.models import Severity
    crit = _sev("C-CRIT", Severity.CRITICAL, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                ["unauthenticated", "extended query parsing", "route wiring"])
    med = _sev("C-MED", Severity.MEDIUM, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
               ["secret is live/unrotated"])
    assert calibrate_score(crit) >= 8            # severity floor for critical
    assert calibrate_score(crit) > calibrate_score(med)


def test_severity_floor_values():
    from sec_harness.calibrate import _severity_floor
    from sec_harness.models import Severity
    assert _severity_floor(Severity.CRITICAL) == 8
    assert _severity_floor(Severity.HIGH) == 6
    assert _severity_floor(Severity.MEDIUM) == 4
    assert _severity_floor(Severity.LOW) == 2


def test_inflation_flag_recorded(tmp_path):
    # CRITICAL claimed (base 9) but strong preconditions derive a pre-floor score of 5 -> delta 4;
    # risk_score is floored to 8 for ordering, but the inflation advisory still fires off pre-floor.
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [_crit("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                              ["requires admin token", "non-default config", "local access"])])
    calibrate_findings(ws)
    f = read_findings(ws)[0]
    assert f.risk_score == 8                       # floored (ordering)
    events = [h for h in f.history if h.get("event") == "calibrate:severity-inflated"]
    assert len(events) == 1 and events[0]["delta"] == 4   # 9 (claimed) - 5 (pre-floor derived)


def test_cluster_a_acceptance_ordering(tmp_path):
    """A confirmed critical needs-runtime finding outranks a medium AND enters the plan."""
    from sec_harness.redteam import discriminate
    crit = Finding(id="AUTHZ-0001", rule_id="r", cls="authz",
                   status=FindingStatus.CONFIRMED, severity=Severity.CRITICAL,
                   file="orders.js", line=87, message="unauth order cancel",
                   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H",
                   preconditions=["unauthenticated", "knows order id"],
                   runtime_disposition="needs-runtime")
    med = Finding(id="SECRETS-0002", rule_id="r", cls="secrets",
                  status=FindingStatus.CONFIRMED, severity=Severity.MEDIUM,
                  file=".env.example", line=23, message="committed secret",
                  cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
                  preconditions=["secret is live"], runtime_disposition="needs-runtime")
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [crit, med])
    calibrate_findings(ws)
    by_id = {f.id: f for f in read_findings(ws)}
    crit_score = by_id["AUTHZ-0001"].risk_score
    med_score = by_id["SECRETS-0002"].risk_score
    assert crit_score is not None and med_score is not None
    assert crit_score >= med_score                           # critical never below medium
    assert crit_score >= 8
    disc = discriminate(read_findings(ws), min_risk=7)
    assert "AUTHZ-0001" == disc["needs_runtime"][0].id       # critical ranks first in the plan


def test_calibrate_promotes_runtime_dependent_before_scoring(tmp_path):
    from sec_harness.calibrate import calibrate_findings
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.workspace import Workspace, read_findings, write_findings
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [Finding(id="A", rule_id="r", cls="business-logic",
                                status=FindingStatus.RAW, severity=Severity.LOW,
                                file="a.py", line=1, message="m", runtime_dependent=True)])
    calibrate_findings(ws)
    by = {f.id: f.status for f in read_findings(ws)}
    assert by["A"] is FindingStatus.NEEDS_DEPLOYMENT_TESTING


def test_calibrate_findings_records_stage(tmp_path):
    from sec_harness.state import load_state

    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_f("F-1", "sqli", Severity.HIGH, ["a", "b"])])
    calibrate_findings(ws)
    assert "calibrate" in load_state(ws).stages


def test_malformed_cvss_does_not_crash_batch(tmp_path):
    # O-029: one finding with an invalid metric must NOT zero the others; it falls back to heuristic.
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    good = Finding(id="G", rule_id="r", cls="sqli", status=FindingStatus.CONFIRMED,
                   severity=Severity.HIGH, file="a.py", line=1, message="m",
                   dataflow=["a @ x:1", "-> b @ x:2"])
    bad = Finding(id="B", rule_id="r", cls="secrets", status=FindingStatus.CONFIRMED,
                  severity=Severity.MEDIUM, file="a.py", line=2, message="m",
                  cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:H/A:N")
    write_findings(ws, [good, bad])
    n = calibrate_findings(ws)                 # must not raise
    assert n == 2
    by_id = {f.id: f for f in read_findings(ws)}
    assert by_id["G"].risk_score == 9          # good finding scored normally
    assert by_id["B"].risk_score is not None    # bad-vector finding fell back to heuristic, not crash


def _f_ndt(**kw: Any) -> Finding:
    """Helper to create findings with keyword-only args (for NDT tests)."""
    base: dict[str, Any] = {"id": "F-1", "rule_id": "r", "cls": "authz", "status": FindingStatus.CONFIRMED,
                            "severity": Severity.MEDIUM, "file": "a.py", "line": 1, "message": "m",
                            "evidence_sources": ["semgrep:rule"]}
    base.update(kw)
    return Finding(**base)


def test_scores_needs_deployment_testing(tmp_path: Path):
    """needs-deployment-testing findings should be scored like confirmed."""
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [_f_ndt(id="NDT-1", status=FindingStatus.NEEDS_DEPLOYMENT_TESTING,
                               severity=Severity.HIGH, evidence_sources=["structural-index:callers"])])
    n = calibrate_findings(ws)
    out = {f.id: f for f in read_findings(ws)}
    assert out["NDT-1"].risk_score is not None
    assert out["NDT-1"].risk_score >= 6  # high severity floor
    assert n >= 1


def test_still_scores_confirmed(tmp_path: Path):
    """Confirmed findings continue to be scored."""
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [_f_ndt(id="C-1", severity=Severity.MEDIUM)])
    calibrate_findings(ws)
    assert read_findings(ws)[0].risk_score is not None


def test_judge_downgrade_lowers_below_severity_floor(tmp_path: Path):
    ws = Workspace(tmp_path)
    ws.ensure()
    # HIGH severity (floor 6) but 3 strong preconditions drive derived score low,
    # and the judge said the severity is inflated -> score should follow derived, not the floor.
    write_findings(ws, [_f_ndt(id="J-1", severity=Severity.HIGH, judge_verdict="severity-inflated",
                               preconditions=["requires admin", "non-default config", "chained from prior primitive"],
                               evidence_sources=["semgrep:rule"])])
    calibrate_findings(ws)
    f = read_findings(ws)[0]
    assert f.risk_score is not None
    assert f.risk_score < 6, "judge severity-inflated must drop below the HIGH floor"
    assert any(h.get("event") == "calibrate:judge-downgrade-applied" for h in f.history)


def test_judge_uphold_does_not_lower(tmp_path: Path):
    ws = Workspace(tmp_path)
    ws.ensure()
    write_findings(ws, [_f_ndt(id="U-1", severity=Severity.HIGH, judge_verdict="uphold",
                               evidence_sources=["semgrep:rule"])])
    calibrate_findings(ws)
    result = read_findings(ws)[0].risk_score
    assert result is not None
    assert result >= 6  # floor intact
