"""Tests for the ScanProfile model."""

import json
from pathlib import Path

import pytest

from sec_harness.profile import ScanProfile, load_profile, save_profile, validate_profile


def _valid_dict():
    return {
        "languages": ["python"],
        "frameworks": ["flask"],
        "entrypoints": ["app.py:get_user"],
        "runnable": False,
        "attack_surface": ["sqli", "secrets"],
        "sast_plan": {
            "semgrep": {"run": True, "rulesets": ["rules/smoke.yaml"]},
            "codeql": {"run": False, "reason": "not justified"},
            "sca": {"run": True, "lockfiles": ["requirements.txt"]},
            "secrets": {"run": True},
        },
        "agents_to_spawn": ["sqli", "secrets"],
        "budget_hint": {"max_candidates": 200, "max_investigate_agents": 6},
        "notes": {},
        "subsystems": [],
        "attack_surface_evidence": {},
        "scan_options": {},
    }


def test_scanprofile_roundtrip():
    d = _valid_dict()
    assert ScanProfile.from_dict(d).to_dict() == d


def test_validate_accepts_valid():
    assert validate_profile(_valid_dict()) == []


def test_validate_reports_missing_and_type_errors():
    bad = _valid_dict()
    del bad["languages"]
    bad["runnable"] = "no"
    bad["attack_surface"] = [1, 2]
    errs = validate_profile(bad)
    assert any("languages" in e for e in errs)
    assert any("runnable" in e for e in errs)
    assert any("attack_surface" in e for e in errs)


def test_load_profile_roundtrip(tmp_path):
    p = tmp_path / "scan-profile.json"
    prof = load_profile_from_dict_helper(p)
    assert prof.languages == ["python"]


def load_profile_from_dict_helper(p):
    save_profile(p, __import__("sec_harness.profile", fromlist=["ScanProfile"]).ScanProfile.from_dict(_valid_dict()))
    return load_profile(p)


def test_load_profile_rejects_invalid(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"languages": ["python"]}))
    with pytest.raises(ValueError):
        load_profile(p)


def test_golden_profile_validates():
    import json
    from pathlib import Path

    golden = Path(__file__).parent.parent / "fixtures" / "golden_scan_profile.json"
    d = json.loads(golden.read_text())
    assert validate_profile(d) == []


def _base(**kw) -> dict:
    d = {"languages": [], "frameworks": [], "entrypoints": [], "runnable": False,
         "attack_surface": [], "sast_plan": {}, "agents_to_spawn": [], "budget_hint": {}}
    d.update(kw)
    return d


def test_scan_options_roundtrips(tmp_path: Path):
    p = tmp_path / "sp.json"
    save_profile(p, ScanProfile(scan_options={"adversary_depth": "gate-by-exception",
                                              "wave_k": 3, "token_budget": 500000}))
    prof = load_profile(p)
    assert prof.scan_options["adversary_depth"] == "gate-by-exception"
    assert prof.scan_options["wave_k"] == 3


def test_absent_scan_options_defaults_empty(tmp_path):
    p = tmp_path / "sp.json"; p.write_text(json.dumps(_base()))
    assert load_profile(p).scan_options == {}


def test_non_dict_scan_options_rejected():
    assert any("scan_options" in e for e in validate_profile(_base(scan_options=["x"])))


def test_profile_notes_roundtrip_and_optional(tmp_path):
    import json as _json

    from sec_harness.profile import ScanProfile, load_profile
    # notes optional: a profile without it still loads
    base = {"languages": ["php"], "frameworks": ["Zend Framework 1"], "entrypoints": [],
            "runnable": True, "attack_surface": ["crypto"], "sast_plan": {"semgrep": {"run": True}},
            "agents_to_spawn": ["crypto"], "budget_hint": {}}
    p = tmp_path / "p.json"; p.write_text(_json.dumps(base))
    assert load_profile(str(p)).notes == {}
    # notes carried through round-trip
    prof = ScanProfile(**base, notes={"eol_frameworks": ["Zend Framework 1"]})
    assert ScanProfile.from_dict(prof.to_dict()).notes == {"eol_frameworks": ["Zend Framework 1"]}
