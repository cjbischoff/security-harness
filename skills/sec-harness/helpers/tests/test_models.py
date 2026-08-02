"""Tests for the Finding / CampaignState models."""

from sec_harness.models import CampaignState, Finding, FindingStatus, Severity


def test_finding_roundtrip_preserves_all_fields():
    f = Finding(
        id="F-0001",
        rule_id="python.sqli.format-string",
        cls="sqli",
        status=FindingStatus.CANDIDATE,
        severity=Severity.HIGH,
        file="app.py",
        line=42,
        message="Tainted input flows into SQL string",
        dataflow=["request.args['q'] @ app.py:10", "-> execute @ app.py:42"],
        evidence="cur.execute(f\"select ... {q}\")",
        risk_score=None,
        verification=None,
        patch_diff=None,
        discovery_sha="abc1234",
        duplicate_of=None,
        history=[],
    )
    assert Finding.from_dict(f.to_dict()) == f


def test_finding_status_and_severity_serialize_as_strings():
    f = Finding.from_dict(
        {
            "id": "F-1",
            "rule_id": "r",
            "cls": "secrets",
            "status": "candidate",
            "severity": "critical",
            "file": "a.py",
            "line": 1,
            "message": "m",
            "dataflow": [],
            "evidence": "",
            "risk_score": None,
            "verification": None,
            "patch_diff": None,
            "discovery_sha": None,
            "duplicate_of": None,
            "history": [],
        }
    )
    assert f.severity is Severity.CRITICAL
    assert f.to_dict()["status"] == "candidate"


def test_campaign_state_roundtrip():
    s = CampaignState(pass_number=3, active_sha="abc", stages={"prefilter": "done"}, budget={})
    assert CampaignState.from_dict(s.to_dict()) == s


def test_finding_new_fields_roundtrip_and_backcompat():
    f = Finding(id="F-1", rule_id="r", cls="sqli", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="a.py", line=1, message="m",
                fingerprint="abc123", priority="P1", cvss_vector="CVSS:3.1/AV:N/...",
                evidence="snippet", evidence_sources=["codeql:dataflow", "llm-claimed:reachable"])
    assert Finding.from_dict(f.to_dict()) == f
    # backward-compat: old dict without the new keys still loads with defaults
    old = {"id": "F-2", "rule_id": "r", "cls": "sqli", "status": "raw", "severity": "high",
           "file": "a.py", "line": 1, "message": "m", "dataflow": [], "evidence": "",
           "risk_score": None, "verification": None, "patch_diff": None,
           "discovery_sha": None, "duplicate_of": None, "history": []}
    g = Finding.from_dict(old)
    assert g.fingerprint is None and g.priority is None and g.cvss_vector is None and g.evidence_sources == []


def test_new_optional_fields_roundtrip():
    from sec_harness.models import Finding, FindingStatus, Severity
    f = Finding(id="F1", rule_id="r", cls="sqli", status=FindingStatus.CONFIRMED,
                severity=Severity.HIGH, file="a.py", line=1, message="m",
                asvs_ids=["v5.0.0-1.2.4"], codeguard_ids=["codeguard-0-input-validation-injection"],
                completeness_tier="FULL")
    d = Finding.from_dict(f.to_dict())
    assert d.asvs_ids == ["v5.0.0-1.2.4"] and d.completeness_tier == "FULL"


def test_from_dict_tolerates_unknown_keys():
    from sec_harness.models import Finding, FindingStatus, Severity
    base = Finding(id="F1", rule_id="r", cls="sqli", status=FindingStatus.RAW,
                   severity=Severity.LOW, file="a", line=1, message="m").to_dict()
    base["future_field"] = "x"
    assert Finding.from_dict(base).id == "F1"   # unknown key dropped, no crash


def test_needs_deployment_status():
    from sec_harness.models import FindingStatus
    assert FindingStatus("needs-deployment-testing") is FindingStatus.NEEDS_DEPLOYMENT_TESTING


def test_runtime_dependent_field_roundtrips_and_defaults_false():
    from sec_harness.models import Finding, FindingStatus, Severity
    f = Finding(id="F-1", rule_id="r", cls="business-logic", status=FindingStatus.RAW,
                severity=Severity.LOW, file="a.py", line=1, message="m")
    assert f.runtime_dependent is False
    f.runtime_dependent = True
    assert Finding.from_dict(f.to_dict()).runtime_dependent is True


def test_informational_status_roundtrips_and_is_terminal():
    from sec_harness.campaign import TERMINAL_STATUSES
    from sec_harness.models import Finding, FindingStatus
    f = Finding(id="C-1", rule_id="r", cls="log-injection", status=FindingStatus.INFORMATIONAL,
                severity=__import__("sec_harness.models", fromlist=["Severity"]).Severity.INFO,
                file="a.py", line=1, message="noise")
    d = f.to_dict()
    assert d["status"] == "informational"
    assert Finding.from_dict(d).status is FindingStatus.INFORMATIONAL
    assert FindingStatus.INFORMATIONAL in TERMINAL_STATUSES
