"""Tests for Bucket C: reachability gate, fail-open parse, salvage/terminal, stage-validate."""

from sec_harness import parse, reachability, stage_validate
from sec_harness.campaign import TERMINAL_STATUSES, salvage_partial
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.profile import ScanProfile, validate_profile
from sec_harness.workspace import Workspace, read_findings, write_findings


def _f(fid, status=FindingStatus.CONFIRMED, reach=None):
    return Finding(id=fid, rule_id="r", cls="sqli", status=status, severity=Severity.HIGH,
                   file="a.py", line=1, message="m", reachability=reach)


# ---- reachability (C2) ----

def test_unassessed_is_reachable():
    assert reachability.is_reachable(_f("F-1", reach=None))  # recall-safe default


def test_reachable_and_blocked():
    r = _f("F-2", reach={"reachable": True, "chain": ["a.py:1", "a.py:2"]})
    b = _f("F-3", reach={"reachable": False, "blocker": "auth_check", "chain": []})
    assert reachability.is_reachable(r) and reachability.blocker_of(r) is None
    assert not reachability.is_reachable(b) and reachability.blocker_of(b) == "auth_check"
    part = reachability.partition([r, b])
    assert [f.id for f in part["reachable"]] == ["F-2"]
    assert [f.id for f in part["blocked"]] == ["F-3"]


def test_validate_reachability_requires_blocker():
    assert reachability.validate_reachability({"reachable": False}) != []
    assert reachability.validate_reachability({"reachable": False, "blocker": "sanitizer"}) == []
    assert reachability.validate_reachability(None) == []


# ---- fail-open parse (C6) ----

def test_extract_plain_and_fenced_and_embedded():
    assert parse.extract_json('{"a": 1}') == {"a": 1}
    assert parse.extract_json('prose\n```json\n{"a": 2}\n```\ntail') == {"a": 2}
    assert parse.extract_json('here is {"a": 3, "b": [1,2]} done') == {"a": 3, "b": [1, 2]}


def test_extract_fails_open_to_none():
    # Unparseable -> None (surfaced), never a silent empty dict/list.
    assert parse.extract_json("no json here at all") is None
    assert parse.extract_json("") is None


def test_extract_ignores_braces_in_strings():
    assert parse.extract_json('{"a": "}{ not real"}') == {"a": "}{ not real"}


# ---- salvage + terminal statuses (C4) ----

def test_terminal_statuses_membership():
    assert FindingStatus.CONFIRMED in TERMINAL_STATUSES
    assert FindingStatus.RAW not in TERMINAL_STATUSES  # non-terminal -> retried on resume


def test_salvage_stamps_partial_raw(tmp_path):
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [_f("R-1", status=FindingStatus.RAW),
                        _f("C-1", status=FindingStatus.CONFIRMED)])
    salvaged = salvage_partial(ws, "agent hit max-turns")
    assert salvaged == ["R-1"]  # only the raw partial, not the confirmed
    r1 = {f.id: f for f in read_findings(ws)}["R-1"]
    assert any(h.get("event") == "salvaged" for h in r1.history)
    # idempotent: a second call does not double-stamp
    assert salvage_partial(ws, "again") == []


# ---- stage-validate (C1) ----

def test_stage_validate_dispatch():
    good = ScanProfile(languages=["python"]).to_dict()
    assert stage_validate.validate_stage("recon", good) == []
    assert stage_validate.validate_stage("recon", {"languages": "nope"}) != []
    assert stage_validate.validate_stage("reachability", {"reachable": False}) != []
    assert stage_validate.validate_stage("runtime_test", {"payloads": []}) != []  # no objective
    assert stage_validate.validate_stage("unknown-stage", {"x": 1}) == []  # no schema -> pass


def test_repair_prompt_quotes_errors():
    p = stage_validate.repair_prompt("recon", {"bad": 1}, ["missing required field: languages"])
    assert "missing required field: languages" in p and "Re-emit ONLY" in p


# ---- profile subsystems (C5) ----

def test_profile_roundtrips_subsystems():
    prof = ScanProfile(languages=["go"], subsystems=[{"name": "parser", "paths": ["p/"], "why": "x"}])
    d = prof.to_dict()
    assert validate_profile(d) == []  # subsystems optional, valid
    assert ScanProfile.from_dict(d).subsystems[0]["name"] == "parser"
