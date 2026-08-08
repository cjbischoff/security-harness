"""Machine-checked coverage-completeness ledger (kb/coverage-ledger.json).

Complements coverage.py's per-language tool-tier accounting with a surface-level
completeness ledger whose central invariant is enforced in code: a scan may not claim
``completeness == "complete"`` while any surface is ``needs_follow_up``, any item is
deferred, or any question is still open. Keeps "gaps logged, never silently dropped" a
machine fact, not a promise.
"""

from __future__ import annotations

import json

from sec_harness.models import FindingStatus
from sec_harness.workspace import Workspace, read_findings

_DISPOSITIONS = {"reported", "no_issue_found", "rejected", "not_applicable", "needs_follow_up"}
_COMPLETENESS = {"complete", "partial", "unknown"}


_REPORTED = {FindingStatus.CONFIRMED, FindingStatus.FIXED, FindingStatus.NEEDS_DEPLOYMENT_TESTING}
_SETTLED_NO_ISSUE = {FindingStatus.REJECTED, FindingStatus.INFORMATIONAL}


def build_coverage_ledger(ws: Workspace) -> dict:
    """Derive + persist the coverage-completeness ledger from attack_surface × findings.

    One surface per non-``deps`` ``attack_surface`` class:
    ``reported`` (≥1 confirmed/fixed/needs-deployment-testing finding), ``no_issue_found``
    (only rejected/informational findings), or ``needs_follow_up`` (no finding at all — an
    uncovered class). ``completeness`` is ``complete`` only when no surface needs follow-up,
    else ``partial``; ``unknown`` when there is no scan-profile. Writes
    ``kb/coverage-ledger.json`` and returns the ledger.

    Args:
        ws: Workspace to read the profile + findings from and write the ledger into.

    Returns:
        The coverage-ledger dict (also persisted).
    """
    prof_path = ws.kb / "scan-profile.json"
    if not prof_path.exists():
        ledger: dict = {
            "completeness": "unknown", "surfaces": [], "deferred": [], "open_questions": [],
        }
        ws.kb.mkdir(parents=True, exist_ok=True)
        (ws.kb / "coverage-ledger.json").write_text(json.dumps(ledger, indent=2))
        return ledger
    profile = json.loads(prof_path.read_text())
    classes = [c for c in profile.get("attack_surface", []) if c != "deps"]
    by_cls: dict[str, list[FindingStatus]] = {}
    for f in read_findings(ws):
        by_cls.setdefault(f.cls, []).append(f.status)
    surfaces = []
    for cls in classes:
        statuses = by_cls.get(cls, [])
        if any(s in _REPORTED for s in statuses):
            disp = "reported"
        elif statuses and all(s in _SETTLED_NO_ISSUE for s in statuses):
            disp = "no_issue_found"
        else:
            # no findings, or non-terminal statuses (RAW/CANDIDATE/STALE/DUPLICATE) remain
            disp = "needs_follow_up"
        surfaces.append({"id": cls, "disposition": disp})
    completeness = (
        "complete"
        if not any(s["disposition"] == "needs_follow_up" for s in surfaces)
        else "partial"
    )
    ledger = {"completeness": completeness, "surfaces": surfaces,
              "deferred": [], "open_questions": []}
    (ws.kb / "coverage-ledger.json").write_text(json.dumps(ledger, indent=2))
    return ledger


def validate_coverage_ledger(d: dict) -> list[str]:
    """Validate a coverage ledger; empty list == valid.

    Args:
        d: The ledger ``{completeness, surfaces[], deferred[], ...}``.

    Returns:
        Human-readable error strings; empty when valid. Enforces the completeness
        invariant: ``complete`` forbids ``needs_follow_up`` surfaces, a non-empty
        ``deferred``, and a non-empty ``open_questions``.
    """
    if not isinstance(d, dict):
        return ["coverage-ledger must be an object"]
    errs: list[str] = []
    completeness = d.get("completeness")
    if completeness not in _COMPLETENESS:
        errs.append(f"coverage-ledger.completeness must be one of {sorted(_COMPLETENESS)}")
    surfaces = d.get("surfaces")
    if not isinstance(surfaces, list):
        errs.append("coverage-ledger.surfaces must be a list")
        surfaces = []
    for i, s in enumerate(surfaces):
        if not isinstance(s, dict) or s.get("disposition") not in _DISPOSITIONS:
            errs.append(f"coverage-ledger.surfaces[{i}].disposition must be one of "
                        f"{sorted(_DISPOSITIONS)}")
    deferred = d.get("deferred", [])
    if not isinstance(deferred, list):
        errs.append("coverage-ledger.deferred must be a list")
        deferred = []
    open_questions = d.get("open_questions", [])
    if not isinstance(open_questions, list):
        errs.append("coverage-ledger.open_questions must be a list")
        open_questions = []
    if completeness == "complete":
        if deferred:
            errs.append("completeness=complete forbids a non-empty deferred[]")
        if open_questions:
            errs.append("completeness=complete forbids a non-empty open_questions[]")
        if any(isinstance(s, dict) and s.get("disposition") == "needs_follow_up"
               for s in surfaces):
            errs.append("completeness=complete forbids any surface with "
                        "disposition=needs_follow_up")
    return errs


def render_markdown(d: dict) -> str:
    """Render the coverage ledger as a report section.

    Args:
        d: The coverage ledger.

    Returns:
        A Markdown "Coverage completeness" section listing surfaces and deferred gaps.
    """
    lines = ["## Coverage completeness", "",
             f"Completeness: **{d.get('completeness', 'unknown')}**", "",
             "| Surface | Disposition |", "|---------|-------------|"]
    for s in d.get("surfaces", []):
        lines.append(f"| {s.get('id', '?')} | {s.get('disposition', '?')} |")
    deferred = d.get("deferred", [])
    if deferred:
        lines += ["", "Deferred (not examined this pass):"]
        lines += [f"- {item}" for item in deferred]
    return "\n".join(lines)
