"""Deterministic cross-repo edges over ingested findings (B-Plan 1: no LLM, no source reads)."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sec_harness.correlate.ingest import IngestedFinding


@dataclass
class Edge:
    """One cross-repo edge over ingested findings.

    Attributes:
        type: The edge type (e.g. ``shared-dependency``).
        members: List of member keys the edge spans.
        key: The join key (OSV id, cls+shape, etc.).
        detail: Additional edge metadata (e.g. ``reachability`` dict).
    """

    type: str
    members: list[str]
    key: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict (members sorted for determinism).

        Returns:
            A dictionary with sorted members list for consistent output.
        """
        d = asdict(self)
        d["members"] = sorted(self.members)
        return d


def _osv_id(f: IngestedFinding) -> str | None:
    """Extract the OSV id from a deps finding's rule_id / evidence_sources, or None.

    Args:
        f: The ingested finding.

    Returns:
        The OSV identifier (e.g. ``GHSA-xxxx-yyyy-zzzz``), or None if not found.
    """
    if f.finding.rule_id.startswith("osv:"):
        return f.finding.rule_id.split(":", 1)[1]
    for s in f.finding.evidence_sources:
        if s.startswith("sca:osv:"):
            return s.split("sca:osv:", 1)[1]
        if s.startswith("osv:"):
            return s.split("osv:", 1)[1]
    return None


def shared_dependency_edges(ings: list[IngestedFinding]) -> list[Edge]:
    """Roll up the same OSV vulnerability seen across ≥2 members into one edge.

    Groups ``cls=="deps"`` findings by OSV id (parsed from ``rule_id`` or
    ``evidence_sources``), and emits one ``shared-dependency`` edge per OSV id
    present in ≥2 distinct member keys. The edge's ``detail.reachability`` maps
    each member key to that member's severity for the dependency.

    Args:
        ings: All ingested findings.

    Returns:
        List of ``shared-dependency`` edges (one per OSV id with ≥2 members),
        sorted by key for determinism. Each edge includes a ``reachability``
        dict mapping member key to severity.
    """
    by_osv: dict[str, dict[str, str]] = defaultdict(dict)
    for i in ings:
        if i.finding.cls != "deps":
            continue
        osv = _osv_id(i)
        if osv:
            by_osv[osv][i.member_key] = i.finding.severity.value
    edges = [Edge(type="shared-dependency", members=list(reach), key=osv,
                  detail={"reachability": reach})
             for osv, reach in by_osv.items() if len(reach) >= 2]
    return sorted(edges, key=lambda e: e.key)


def write_edges(path: str | Path, edges: list[Edge]) -> None:
    """Write edges to a JSON file (sorted, deterministic).

    Args:
        path: Output file path.
        edges: List of edges to serialize.
    """
    Path(path).write_text(json.dumps([e.to_dict() for e in edges], indent=2))
