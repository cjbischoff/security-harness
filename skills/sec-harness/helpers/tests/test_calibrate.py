"""Tests for deterministic risk calibration."""

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


def test_precondition_cap_lowers_score():
    crit_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 -> 10
    assert calibrate_score(_crit(crit_vec, [])) == 10             # 0 preconds -> no cap
    assert calibrate_score(_crit(crit_vec, ["auth"])) == 8        # 1 -> cap 8
    assert calibrate_score(_crit(crit_vec, ["auth", "cfg"])) == 7  # 2 -> cap 7
    assert calibrate_score(_crit(crit_vec, ["auth", "cfg", "local"])) == 5  # 3+ -> cap 5


def test_inflation_flag_recorded(tmp_path):
    # CRITICAL claimed (base 9) but 3 preconditions cap the derived score to 5 -> delta 4.
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [_crit("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                               ["auth", "cfg", "local"])])
    calibrate_findings(ws)
    f = read_findings(ws)[0]
    assert f.risk_score == 5
    events = [h for h in f.history if h.get("event") == "calibrate:severity-inflated"]
    assert len(events) == 1 and events[0]["delta"] == 4
