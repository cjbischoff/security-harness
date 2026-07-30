"""Normalize raw detector output: dedup overlapping candidates, assign stable ids."""

from __future__ import annotations

from sec_harness.models import Finding

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings and assign stable, sorted ids.

    Duplicates are keyed by ``(file, line, cls)``; the highest-severity member
    of each group survives. Survivors are sorted by ``(file, line, cls)`` and
    reassigned ids ``F-0001``, ``F-0002``, ...

    Args:
        findings: Raw candidate findings from one or more detectors.

    Returns:
        Deduplicated findings with stable ids.
    """
    best: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.file, f.line, f.cls)
        cur = best.get(key)
        if cur is None or _SEVERITY_ORDER[f.severity.value] > _SEVERITY_ORDER[cur.severity.value]:
            best[key] = f
    survivors = sorted(best.values(), key=lambda f: (f.file, f.line, f.cls))
    for i, f in enumerate(survivors, start=1):
        f.id = f"F-{i:04d}"
    return survivors
