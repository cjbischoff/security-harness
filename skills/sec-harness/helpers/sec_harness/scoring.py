"""Deterministic fix-validation scoring (weighted gates, non-waivable regression).

Adversarial personas supply per-gate statuses + evidence; this module computes
the verdict — never the LLM. Adapted from VVAH's validation scoring engine.
"""

from __future__ import annotations

_WEIGHTS = {
    "root_cause": 0.43,
    "instance_coverage": 0.25,
    "no_new_vulnerabilities": 0.19,
    "best_practices": 0.13,
}
_MULT = {"pass": 1.0, "partial": 0.5, "fail": 0.0}
_CRITICAL = "no_new_vulnerabilities"


def score_fix(gates: dict[str, str]) -> tuple[str, float]:
    """Score a proposed fix from adversarial gate statuses.

    Args:
        gates: Map of the four gate names to a status in
            ``{pass, partial, fail, skip, invalid}``.

    Returns:
        ``(verdict, score)`` with verdict in
        ``{fixed, partial, not_fixed, unverifiable}``.
    """
    crit = gates.get(_CRITICAL, "invalid")
    if crit in ("skip", "invalid"):
        return "unverifiable", 0.0

    num = 0.0
    denom = 0.0
    for name, weight in _WEIGHTS.items():
        status = gates.get(name, "invalid")
        if status == "skip":
            continue  # neutral: drop from both num and denom
        denom += weight
        if status == "invalid":
            continue  # fail-closed: contributes 0 to num, stays in denom
        num += weight * _MULT.get(status, 0.0)

    if denom < 0.50:
        return "unverifiable", 0.0
    score = num / denom

    if score >= 0.80:
        verdict = "fixed"
    elif score >= 0.50:
        verdict = "partial"
    else:
        verdict = "not_fixed"

    # non-waivable regression cap: a partial/fail critical gate can never be "fixed"
    if crit in ("partial", "fail") and verdict == "fixed":
        verdict = "partial"
    return verdict, round(score, 4)
