"""Tests for F11 fix_disposition, F12 gates, F13 crypto_policy."""
import json
from pathlib import Path

from sec_harness.crypto_policy import check
from sec_harness.fix_disposition import compute_tier, validate
from sec_harness.gates import GATE_ROUTING, run_gates


# F11
def test_compute_tier_conservative():
    assert compute_tier({"sink_signature_changed": True, "callers_routed": True, "test_discriminates": True}) == "FULL"
    assert compute_tier({"sink_signature_changed": True}) == "MITIGATION"
    assert compute_tier({"test_discriminates": True}) == "WORKAROUND"
    assert compute_tier({}) == "LLM_REVIEW"          # never silently FULL


def test_validate_cross_field_honesty():
    assert validate({"completeness_tier": "FULL", "status": "VERIFIED_FULL",
                     "residual_vectors": [], "discrimination_evidence": {"pre": "fail", "post": "pass"}}) == []
    assert any("residual" in e for e in validate({"completeness_tier": "FULL", "status": "VERIFIED_FULL", "residual_vectors": ["x"]}))
    assert any("residual" in e for e in validate({"completeness_tier": "MITIGATION", "status": "VERIFIED_MITIGATION", "residual_vectors": []}))
    assert any("discrimination" in e for e in validate({"completeness_tier": "FULL", "status": "VERIFIED_FULL", "residual_vectors": []}))
    assert any("sweep_revised" in e for e in validate({"completeness_tier": "FULL", "status": "VERIFIED_FULL", "residual_vectors": [], "discrimination_evidence": {"pre":"fail","post":"pass"}, "sweep_revised": True}))


def test_disposition_schema_exists_and_matches_enums():
    schema = json.loads((Path(__file__).resolve().parents[2] / "references" / "fix-disposition.schema.json").read_text())
    assert schema["properties"]["completeness_tier"]["enum"] == ["FULL", "MITIGATION", "WORKAROUND"]


# F12
def test_run_gates_fail_closed():
    good = {"changed_files": ["a.py", "t_test.py"], "files_modified": ["a.py"], "test_file": "t_test.py",
            "vulnfix_key": "0123456789abcdef", "verification_table": [], "id": "F1"}
    assert run_gates(good)["pass"] is True
    # out-of-scope edit fails
    bad = dict(good, changed_files=["a.py", "evil.py"])
    assert run_gates(bad)["pass"] is False
    # missing result hard-fails
    assert run_gates(None)["pass"] is False
    # committed scaffold fails
    scaffold = dict(good, changed_files=["a.py", "verify_VULN-001.py"])
    assert run_gates(scaffold)["gates"]["committed-test-naming"]["ok"] is False


def test_run_gates_required_not_run_fails(monkeypatch):
    # simulate routing drift: drop a required gate from the table -> vacuous pass guard
    monkeypatch.setitem(GATE_ROUTING, "scope", GATE_ROUTING["scope"])
    saved = dict(GATE_ROUTING)
    try:
        GATE_ROUTING.pop("scope")
        res = run_gates({"changed_files": [], "files_modified": [], "vulnfix_key": "0123456789abcdef", "verification_table": []})
        assert res["pass"] is False and "did not run" in res.get("error", "")
    finally:
        GATE_ROUTING.clear(); GATE_ROUTING.update(saved)


# F13
def test_crypto_policy():
    assert check("md5")["ok"] is False
    assert check("rsa", {"rsa": 2048}, "literal")["violations"]
    assert check("aes-256-gcm", {"aes": 256}, "kms")["ok"] is True
