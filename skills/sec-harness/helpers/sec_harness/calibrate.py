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
# Severity-from-preconditions (reference-tool rule): more/harder preconditions cap risk.
# 0 preconditions (unauth/remote/no setup) → no cap; 1-2 → cap 8/7; 3+ → cap 5.
_PRECOND_CAP = {0: 10, 1: 8, 2: 7}
# A claimed severity this far above the derived score is flagged as inflation (recall-safe:
# we flag, we do not silently drop or re-score).
_INFLATION_THRESHOLD = 3


def _is_baseline_standard(finding: Finding) -> bool:
    return any(h.get("event") == "baseline:industry-standard" for h in finding.history)


def _precondition_cap(n: int) -> int:
    """Risk-score ceiling for a finding with ``n`` preconditions (3+ → 5)."""
    return _PRECOND_CAP.get(n, 5)


def _heuristic_score(finding: Finding) -> int:
    """Fallback score when no (valid) CVSS vector is present."""
    score = _BASE.get(finding.severity.value, 1)
    if len(finding.dataflow) >= 2:
        score += 1
    if finding.cls in _HIGH_IMPACT:
        score += 1
    return max(1, min(10, score))


def calibrate_score(finding: Finding) -> int:
    """Compute a 1-10 risk score from CVSS/severity, then apply the precondition + baseline caps.

    Args:
        finding: The finding to score.

    Returns:
        An integer in ``[1, 10]``: the CVSS 3.1 base (rounded) if a valid vector is present,
        else the severity heuristic (+1 for >=2-hop dataflow, +1 for a high-impact class); then
        lowered to the precondition ceiling (more preconditions → lower) and the baseline cap.
    """
    raw = None
    if finding.cvss_vector:
        try:
            raw = max(1, min(10, round(cvss31_base(finding.cvss_vector)[0])))
        except ValueError:
            raw = None  # malformed -> heuristic
    if raw is None:
        raw = _heuristic_score(finding)
    raw = min(raw, _precondition_cap(len(finding.preconditions)))
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
            f.risk_score = calibrate_score(f)
            delta = inflation_delta(f, f.risk_score)
            if delta >= _INFLATION_THRESHOLD and not any(
                h.get("event") == "calibrate:severity-inflated" for h in f.history
            ):
                f.history.append({"event": "calibrate:severity-inflated",
                                  "claimed": f.severity.value, "derived": f.risk_score,
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
