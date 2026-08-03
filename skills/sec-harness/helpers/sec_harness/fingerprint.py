"""Stable content-hash fingerprints for findings.

A fingerprint is a deterministic hash of a finding's identity. Identity is
``rule_id|cls|anchor`` where ``anchor`` is the enclosing symbol name (resolved by
the caller via :func:`sec_harness.graph.symbol_at`) so identity survives line
shifts. When no anchor is available (no substrate) it degrades to ``file:line`` —
the pre-substrate behavior. Enables cross-tool dedup and cross-pass diffing.
"""

from __future__ import annotations

import hashlib

from sec_harness.models import Finding


def fingerprint(finding: Finding, anchor: str | None = None) -> str:
    """Return a stable 12-hex-char fingerprint of a finding's identity.

    Args:
        finding: The finding to fingerprint.
        anchor: The enclosing-symbol name (refactor-resistant identity component).
            When ``None``, identity degrades to ``file:line``.

    Returns:
        ``sha256("{rule_id}|{cls}|{anchor-or-file:line}")`` truncated to 12 hex chars.
    """
    a = anchor if anchor is not None else f"{finding.file}:{finding.line}"
    key = f"{finding.rule_id}|{finding.cls}|{a}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def diff_findings(prev: list[Finding], cur: list[Finding]) -> dict[str, list[str]]:
    """Partition two finding sets by fingerprint.

    Prefers each finding's already-stamped ``.fingerprint`` (set by dedupe using the
    substrate anchor) so a finding that only moved lines matches across passes; falls
    back to recomputing when a finding was never stamped.

    Args:
        prev: Findings from a prior pass.
        cur: Findings from the current pass.

    Returns:
        ``{"new", "resolved", "still_flagged"}`` — sorted fingerprint lists.
    """
    def _fp(f: Finding) -> str:
        return f.fingerprint or fingerprint(f)

    p = {_fp(f) for f in prev}
    c = {_fp(f) for f in cur}
    return {
        "new": sorted(c - p),
        "resolved": sorted(p - c),
        "still_flagged": sorted(p & c),
    }
