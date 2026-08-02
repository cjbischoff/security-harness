"""Deterministic risk calibration: assign a 1-10 score to confirmed findings."""

from __future__ import annotations

import argparse
from pathlib import Path

from sec_harness.cvss import cvss31_base, offensive_priority
from sec_harness.models import Finding, FindingStatus
from sec_harness.workspace import Workspace, read_findings, write_findings

_BASE = {"critical": 9, "high": 7, "medium": 5, "low": 3, "info": 1}
_HIGH_IMPACT = {"sqli", "cmdi", "deserialization", "ssti", "authz", "ssrf", "path-traversal", "secrets"}
# F10: a pattern the validate agent judged industry-standard-safe (a comparable
# mainstream app does the same, unexploited in years of prod) is capped low — a
# textbook deviation that a real baseline accepts is not a high-risk finding.
_BASELINE_CAP = 4
# A precondition lowers risk only when it is a real barrier an attacker must overcome.
# Free conditions (unauthenticated/remote/default) are NOT mitigants and never lower risk
# (fixes O-031: enumerating free preconditions must not penalize a finding).
_PRECOND_FREE = ("unauth", "no auth", "without auth", "anonymous", "public", "no config",
                 "default config", "no setup", "remote", "any user", "no special", "no privilege")
_PRECOND_STRONG = ("admin", "operator", "root", "superuser", "non-default", "feature flag",
                   "feature-flag", "local access", "local-only", "physical", "prior primitive",
                   "prior-primitive", "chained", "mitm", "man-in-the-middle",
                   "specific config", "specific configuration", "guessed", "brute")
_PRECOND_WEAK = ("auth", "login", "logged", "session", "account", "one hop", "csrf",
                 "user interaction")
# A claimed severity this far above the derived score is flagged as inflation (recall-safe:
# we flag, we do not silently drop or re-score).
_INFLATION_THRESHOLD = 3
# Severity floor: risk_score must never invert severity ordering (fixes O-031). A medium can
# reach 8 via CVSS (C:L/I:H), so a critical must floor at 8. The floor is applied for ORDERING;
# the inflation flag (advisory) compares against the pre-floor derived score so disagreement is
# still surfaced.
_SEVERITY_FLOOR = {"critical": 8, "high": 6, "medium": 4, "low": 2, "info": 1}


def _is_baseline_standard(finding: Finding) -> bool:
    return any(h.get("event") == "baseline:industry-standard" for h in finding.history)


def _precondition_weight(preconditions: list[str]) -> float:
    """Summed difficulty weight of preconditions (free=0, weak=0.5, strong=1.0, unknown=0)."""
    total = 0.0
    for p in preconditions:
        s = p.lower()
        if any(k in s for k in _PRECOND_STRONG):
            # checked first: "non-default config" must win over FREE's "default config" substring
            total += 1.0
        elif any(k in s for k in _PRECOND_FREE):
            continue  # non-mitigant; checked before weak so "unauth..." never matches "auth"
        elif any(k in s for k in _PRECOND_WEAK):
            total += 0.5
    return total


def _precondition_cap(preconditions: list[str]) -> int:
    """Risk ceiling from precondition DIFFICULTY (weight), not count.

    Args:
        preconditions: The finding's precondition strings.

    Returns:
        Ceiling in ``[5, 10]``: ``w<1 -> 10``, ``1<=w<2 -> 8``, ``2<=w<3 -> 7``, ``w>=3 -> 5``.
    """
    w = _precondition_weight(preconditions)
    if w < 1:
        return 10
    if w < 2:
        return 8
    if w < 3:
        return 7
    return 5


def _severity_floor(severity) -> int:
    """Minimum risk_score implied by the severity band."""
    return _SEVERITY_FLOOR.get(severity.value, 1)


def _heuristic_score(finding: Finding) -> int:
    """Fallback score when no (valid) CVSS vector is present."""
    score = _BASE.get(finding.severity.value, 1)
    if len(finding.dataflow) >= 2:
        score += 1
    if finding.cls in _HIGH_IMPACT:
        score += 1
    return max(1, min(10, score))


def _derived_score(finding: Finding) -> int:
    """Pre-floor score: CVSS/heuristic then precondition cap (NO severity floor)."""
    raw = None
    if finding.cvss_vector:
        try:
            raw = max(1, min(10, round(cvss31_base(finding.cvss_vector)[0])))
        except ValueError:
            raw = None  # malformed -> heuristic
    if raw is None:
        raw = _heuristic_score(finding)
    return min(raw, _precondition_cap(finding.preconditions))


def calibrate_score(finding: Finding) -> int:
    """Compute the 1-10 risk score: derived score, floored by severity, then baseline cap.

    Args:
        finding: The finding to score.

    Returns:
        Int in ``[1, 10]``. Severity floor prevents rank inversion; an industry-standard-safe
        finding is still capped low (baseline cap applied last).
    """
    raw = max(_derived_score(finding), _severity_floor(finding.severity))
    if _is_baseline_standard(finding):
        raw = min(raw, _BASELINE_CAP)
    return raw


def inflation_delta(finding: Finding, score: int) -> int:
    """How far the model's claimed severity tier sits above the derived score (0 if not above).

    A positive delta means the finder rated the finding more severe than the calibrated risk
    supports — a triage-ordering signal, not a re-score.
    """
    claimed = _BASE.get(finding.severity.value, 1)
    return max(0, claimed - score)


def calibrate_findings(ws: Workspace) -> int:
    """Set ``risk_score`` on every confirmed finding in the workspace.

    Args:
        ws: Workspace whose confirmed findings are scored in place.

    Returns:
        The number of findings scored.
    """
    from sec_harness.citations import attach as _attach_citations  # local: avoid cycle
    findings = read_findings(ws)
    scored = 0
    for f in findings:
        if f.status is FindingStatus.CONFIRMED:
            _attach_citations(f)  # F1: auto-attach ASVS/CodeGuard (no-op if already set)
            derived = _derived_score(f)  # pre-floor: floor must not mask inflation
            f.risk_score = calibrate_score(f)
            delta = inflation_delta(f, derived)
            if delta >= _INFLATION_THRESHOLD and not any(
                h.get("event") == "calibrate:severity-inflated" for h in f.history
            ):
                f.history.append({"event": "calibrate:severity-inflated",
                                  "claimed": f.severity.value, "derived": derived,
                                  "delta": delta})
            if f.cvss_vector:
                try:
                    f.priority = offensive_priority(f.cvss_vector)
                except ValueError:
                    pass
            scored += 1
    if scored:
        write_findings(ws, findings)
    return scored


def main(argv: list[str] | None = None) -> int:
    """CLI: calibrate a workspace's confirmed findings.

    Args:
        argv: Optional argument vector.

    Returns:
        0 on success.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-calibrate")
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args(argv)
    n = calibrate_findings(Workspace(Path(args.workspace)))
    print(f"calibrated {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
