"""Reachability verdict + gate (Bucket C2, adapted from audit's trace stage).

A finding carries a ``reachability`` verdict once the trace phase runs: whether a real
untrusted entry point reaches the sink, and if not, WHICH control blocks it (the blocker
taxonomy). This is the discriminator the red-team phase uses to split static-settled from
needs-runtime, and an optional report gate: a finding proven unreachable by a cited blocker
should not ship as an exploitable confirmed finding.

Recall-safe: an UNASSESSED finding (``reachability is None``) is treated as reachable — we
never silently drop a finding just because the trace phase did not run on it.
"""

from __future__ import annotations

from sec_harness.models import Finding

BLOCKERS = ("sanitizer", "auth_check", "input_validation", "dead_code", "feature_flag", "other")


def is_reachable(finding: Finding) -> bool:
    """True if the finding is reachable (or not yet assessed — recall-safe default)."""
    r = finding.reachability
    if not r:
        return True
    return bool(r.get("reachable", True))


def blocker_of(finding: Finding) -> str | None:
    """The cited blocker control when a finding is proven unreachable, else ``None``."""
    r = finding.reachability or {}
    if r.get("reachable", True):
        return None
    b = r.get("blocker")
    return b if b in BLOCKERS else "other"


def partition(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Split findings into ``reachable`` and ``blocked`` (unreachable with a cited blocker)."""
    reachable, blocked = [], []
    for f in findings:
        (reachable if is_reachable(f) else blocked).append(f)
    return {"reachable": reachable, "blocked": blocked}


def validate_reachability(r: dict | None) -> list[str]:
    """Return schema problems with a reachability dict (empty == valid or absent)."""
    if r is None:
        return []
    errs: list[str] = []
    if "reachable" not in r or not isinstance(r["reachable"], bool):
        errs.append("reachability.reachable must be a bool")
    if r.get("reachable") is False and r.get("blocker") not in BLOCKERS:
        errs.append(f"unreachable finding needs a blocker in {BLOCKERS}")
    if "chain" in r and not isinstance(r["chain"], list):
        errs.append("reachability.chain must be a list")
    return errs
