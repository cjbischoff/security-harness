"""Stable content-hash fingerprints for findings.

A fingerprint is a deterministic hash of a finding's identity (rule, class,
location) — stable across tool runs and passes. Enables cross-tool dedup and
cross-pass finding-set diffing (new / resolved / still-flagged). Adapted from
raptor's SARIF finding-id hash and VulnHunter's vulnfix_key.
"""

from __future__ import annotations

import hashlib

from sec_harness.models import Finding


def fingerprint(finding: Finding) -> str:
    """Return a stable 12-hex-char fingerprint of a finding's identity.

    Args:
        finding: The finding to fingerprint.

    Returns:
        ``sha256("{rule_id}|{cls}|{file}|{line}")`` truncated to 12 hex chars.
    """
    key = f"{finding.rule_id}|{finding.cls}|{finding.file}|{finding.line}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def diff_findings(prev: list[Finding], cur: list[Finding]) -> dict[str, list[str]]:
    """Partition two finding sets by fingerprint.

    Args:
        prev: Findings from a prior pass.
        cur: Findings from the current pass.

    Returns:
        ``{"new", "resolved", "still_flagged"}`` — sorted fingerprint lists.
    """
    p = {fingerprint(f) for f in prev}
    c = {fingerprint(f) for f in cur}
    return {
        "new": sorted(c - p),
        "resolved": sorted(p - c),
        "still_flagged": sorted(p & c),
    }
