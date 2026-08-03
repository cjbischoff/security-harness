"""Machine-checked coverage-completeness ledger (kb/coverage-ledger.json).

Complements coverage.py's per-language tool-tier accounting with a surface-level
completeness ledger whose central invariant is enforced in code: a scan may not claim
``completeness == "complete"`` while any surface is ``needs_follow_up``, any item is
deferred, or any question is still open. Keeps "gaps logged, never silently dropped" a
machine fact, not a promise.
"""

from __future__ import annotations

_DISPOSITIONS = {"reported", "no_issue_found", "rejected", "not_applicable", "needs_follow_up"}
_COMPLETENESS = {"complete", "partial", "unknown"}


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
