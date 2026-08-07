"""Deterministic dedupe: merge exact (file, line, cls) finding collisions."""

from __future__ import annotations

import argparse
from pathlib import Path

from sec_harness.campaign import record_stage
from sec_harness.fingerprint import fingerprint
from sec_harness.graph import load_graph, symbol_at
from sec_harness.models import Finding, FindingStatus
from sec_harness.workspace import Workspace, read_findings, write_findings

_ACTIVE = {FindingStatus.RAW, FindingStatus.CONFIRMED}
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def dedupe_findings(ws: Workspace) -> int:
    """Mark exact-duplicate active findings, keeping the highest-severity primary.

    Findings with the same ``(file, line, cls)`` and a status in {RAW, CONFIRMED}
    are collapsed: the highest-severity member (tiebreak: smallest id) stays; the
    rest become ``DUPLICATE`` with ``duplicate_of`` set to the primary's id.
    All active findings are stamped with a stable fingerprint.

    Args:
        ws: Workspace whose findings are deduped in place.

    Returns:
        The number of findings marked as duplicates.
    """
    findings = read_findings(ws)
    marked = 0

    # Honor duplicate_of already set by an investigator (e.g. sibling sinks in one
    # function at different lines, which the exact (file,line,cls) collision check
    # below cannot catch). An active finding that points at an existing primary is
    # demoted to DUPLICATE so it doesn't proceed as a distinct finding through the
    # rest of the ladder (critic/validate/patch) and inflate the report.
    ids = {f.id for f in findings}
    for f in findings:
        if f.status in _ACTIVE and f.duplicate_of and f.duplicate_of in ids:
            f.status = FindingStatus.DUPLICATE
            f.history.append({"event": f"duplicate_of:{f.duplicate_of}"})
            marked += 1

    # Stamp every active finding with a stable fingerprint. Resolve a refactor-
    # resistant anchor from the substrate when present.
    graph = load_graph(ws) if (ws.kb / "graph.json").exists() else None
    for f in findings:
        if f.status in _ACTIVE:
            anchor = symbol_at(graph, f.file, f.line) if graph is not None else None
            f.fingerprint = fingerprint(f, anchor=anchor)
    stamped = True

    groups: dict[tuple[str, int, str, tuple[str, ...] | str], list[Finding]] = {}
    for f in findings:
        if f.status in _ACTIVE:
            key = (f.file, f.line, f.cls, tuple(f.dataflow) or f.message)
            groups.setdefault(key, []).append(f)

    for members in groups.values():
        if len(members) < 2:
            continue
        primary = min(members, key=lambda f: (-_SEVERITY_ORDER[f.severity.value], f.id))
        for f in members:
            if f.id == primary.id:
                continue
            f.status = FindingStatus.DUPLICATE
            f.duplicate_of = primary.id
            f.history.append({"event": f"duplicate_of:{primary.id}"})
            marked += 1

    # Cross-class pass: the same underlying fact (identical file/line/dataflow)
    # can surface under different attack-class framings (e.g. ssrf vs authz).
    # Only merge when dataflow is non-empty, so dataflow-less findings never
    # collide across classes on file/line alone.
    fact_groups: dict[tuple[str, int, tuple[str, ...]], list[Finding]] = {}
    for f in findings:
        if f.status in _ACTIVE and f.dataflow:
            fact_groups.setdefault((f.file, f.line, tuple(f.dataflow)), []).append(f)

    for members in fact_groups.values():
        if len(members) < 2:
            continue
        primary = min(members, key=lambda f: (-_SEVERITY_ORDER[f.severity.value], f.id))
        for f in members:
            if f.id == primary.id:
                continue
            f.status = FindingStatus.DUPLICATE
            f.duplicate_of = primary.id
            f.history.append({"event": f"duplicate_of:{primary.id}"})
            marked += 1

    if marked or stamped:
        write_findings(ws, findings)
    record_stage(ws, "dedupe")
    return marked


def main(argv: list[str] | None = None) -> int:
    """CLI: dedupe a workspace's findings.

    Args:
        argv: Optional argument vector.

    Returns:
        0 on success.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-dedupe")
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args(argv)
    n = dedupe_findings(Workspace(Path(args.workspace)))
    print(f"deduped {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
