from __future__ import annotations

import json
from pathlib import Path

from sec_harness.coverage_ledger import (
    build_coverage_ledger,
    render_markdown,
    validate_coverage_ledger,
)
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, write_findings


def _f(cls: str, status: FindingStatus, fid: str) -> Finding:
    return Finding(id=fid, rule_id="r", cls=cls, status=status, severity=Severity.MEDIUM,
                   file="a.py", line=1, message="m", evidence_sources=["semgrep:x"])


def _profile(ws: Workspace, attack_surface: list[str]) -> None:
    (ws.kb).mkdir(parents=True, exist_ok=True)
    (ws.kb / "scan-profile.json").write_text(json.dumps({
        "languages": ["go"], "frameworks": [], "entrypoints": [], "runnable": False,
        "attack_surface": attack_surface, "sast_plan": {}, "agents_to_spawn": attack_surface,
        "budget_hint": {},
    }))


def test_uncovered_class_blocks_complete(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    _profile(ws, ["authz", "sqli"])
    write_findings(ws, [_f("authz", FindingStatus.CONFIRMED, "A-1")])  # sqli has NO finding
    led = build_coverage_ledger(ws)
    disp = {s["id"]: s["disposition"] for s in led["surfaces"]}
    assert disp["authz"] == "reported"
    assert disp["sqli"] == "needs_follow_up"
    assert led["completeness"] == "partial"
    assert validate_coverage_ledger(led) == []  # partial+needs_follow_up is valid
    # persisted
    assert json.loads((ws.kb / "coverage-ledger.json").read_text())["completeness"] == "partial"


def test_all_covered_is_complete(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    _profile(ws, ["authz", "secrets"])
    write_findings(ws, [_f("authz", FindingStatus.NEEDS_DEPLOYMENT_TESTING, "A-1"),
                        _f("secrets", FindingStatus.REJECTED, "S-1")])
    led = build_coverage_ledger(ws)
    disp = {s["id"]: s["disposition"] for s in led["surfaces"]}
    assert disp["authz"] == "reported"
    assert disp["secrets"] == "no_issue_found"
    assert led["completeness"] == "complete"
    assert validate_coverage_ledger(led) == []


def test_raw_only_class_is_needs_follow_up_not_complete(tmp_path: Path):
    """A class whose only finding is RAW (unadjudicated) must NOT read as no_issue_found.

    This tests Finding 1: the completeness invariant must hold even when findings exist
    but have non-terminal statuses (RAW/CANDIDATE). Such a class is needs_follow_up,
    not no_issue_found, so completeness stays partial.
    """
    ws = Workspace(tmp_path); ws.ensure()
    _profile(ws, ["authz", "sqli"])
    write_findings(ws, [_f("authz", FindingStatus.CONFIRMED, "A-1"),
                        _f("sqli", FindingStatus.RAW, "S-1")])
    led = build_coverage_ledger(ws)
    disp = {s["id"]: s["disposition"] for s in led["surfaces"]}
    assert disp["authz"] == "reported"
    assert disp["sqli"] == "needs_follow_up"   # NOT no_issue_found
    assert led["completeness"] == "partial"     # NOT complete


def test_candidate_only_class_is_needs_follow_up(tmp_path: Path):
    """A class with only CANDIDATE findings is also needs_follow_up."""
    ws = Workspace(tmp_path); ws.ensure()
    _profile(ws, ["sqli"])
    write_findings(ws, [_f("sqli", FindingStatus.CANDIDATE, "S-1")])
    led = build_coverage_ledger(ws)
    assert led["surfaces"][0]["disposition"] == "needs_follow_up"
    assert led["completeness"] == "partial"


def test_deps_excluded_and_no_profile_is_unknown(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()  # no profile written
    led = build_coverage_ledger(ws)
    assert led["completeness"] == "unknown"
    assert led["surfaces"] == []


def _ledger(completeness, surfaces, deferred=None):
    return {"completeness": completeness, "surfaces": surfaces, "deferred": deferred or []}


def test_complete_forbids_needs_follow_up():
    d = _ledger("complete", [{"id": "auth", "disposition": "needs_follow_up"}])
    errs = validate_coverage_ledger(d)
    assert any("needs_follow_up" in e for e in errs)


def test_complete_forbids_nonempty_deferred():
    d = _ledger("complete", [{"id": "auth", "disposition": "reported"}], deferred=["templates"])
    assert any("deferred" in e for e in validate_coverage_ledger(d))


def test_consistent_complete_ledger_is_valid():
    d = _ledger("complete", [{"id": "auth", "disposition": "reported"}])
    assert validate_coverage_ledger(d) == []


def test_complete_forbids_nonempty_open_questions():
    d = _ledger("complete", [{"id": "auth", "disposition": "reported"}])
    d["open_questions"] = ["is the admin route reachable unauthenticated?"]
    assert any("open_questions" in e for e in validate_coverage_ledger(d))


def test_bad_open_questions_type_flagged():
    d = _ledger("partial", [{"id": "auth", "disposition": "reported"}])
    d["open_questions"] = "not-a-list"
    assert any("open_questions" in e for e in validate_coverage_ledger(d))


def test_bad_disposition_flagged():
    d = _ledger("partial", [{"id": "auth", "disposition": "bogus"}])
    assert any("disposition" in e for e in validate_coverage_ledger(d))


def test_render_markdown_lists_deferred():
    d = _ledger("partial", [{"id": "auth", "disposition": "reported"}], deferred=["liquid templates"])
    md = render_markdown(d)
    assert "Coverage completeness" in md and "liquid templates" in md
