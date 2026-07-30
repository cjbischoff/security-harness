"""Variant-hunt seeding (Bucket B1, from audit's feedback stage + dcrh variant hunt).

A confirmed finding is rarely alone: the same shape usually recurs at sibling call sites. This
turns a confirmed finding into deterministic search seeds (the sink token → an rg/ast-grep
pattern) that the variant-hunt agent uses to enqueue fresh candidates within the same run —
turning one confirmed bug into coverage of its family. The agent still confirms each sibling
through the normal gate ladder; these are leads, not findings.
"""

from __future__ import annotations

from sec_harness.models import Finding


def _sink_token(finding: Finding) -> str:
    """Best sink identifier for a sibling search: the sink hop's expr, else the evidence head."""
    if finding.dataflow:
        last = finding.dataflow[-1]
        expr = last.split("@", 1)[0].strip().lstrip("-> ").strip()
        if expr:
            return expr
    return (finding.evidence or "").strip().split("\n", 1)[0][:80]


def variant_seeds(finding: Finding) -> list[dict]:
    """Return sibling-search seeds for a confirmed finding (empty if no usable token).

    Each seed: ``{"kind": "ripgrep"|"ast-grep", "pattern": str, "cls": str, "why": str}``.
    The variant-hunt agent runs these to find other call sites of the same shape, then confirms
    each through the gate ladder.
    """
    token = _sink_token(finding)
    if not token:
        return []
    return [{
        "kind": "ripgrep",
        "pattern": token,
        "cls": finding.cls,
        "why": f"sibling call sites of the {finding.cls} sink confirmed at "
               f"{finding.file}:{finding.line} ({finding.id})",
    }]
