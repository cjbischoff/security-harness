"""Deterministic cross-repo edges over ingested findings (B-Plan 1: no LLM, no source reads)."""

from __future__ import annotations

import json
import re
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


_RECURRENCE_STATUSES = {"confirmed", "needs-deployment-testing", "fixed"}


def same_class_recurrence_edges(ings: list[IngestedFinding]) -> list[Edge]:
    """Flag a shape (fingerprint, else cls:rule_id) recurring across ≥2 members as systemic.

    Args:
        ings: All ingested findings.

    Returns:
        One ``same-class-recurrence`` edge per shape present in ≥2 distinct member keys (only
        findings whose status is confirmed/needs-deployment-testing/fixed count), sorted by key.
    """
    by_shape: dict[str, dict[str, str]] = defaultdict(dict)
    for i in ings:
        if i.finding.status.value not in _RECURRENCE_STATUSES:
            continue
        shape = i.finding.fingerprint or f"{i.finding.cls}:{i.finding.rule_id}"
        by_shape[shape][i.member_key] = i.finding.cls
    edges = [Edge(type="same-class-recurrence", members=list(mk), key=shape,
                  detail={"cls": next(iter(mk.values())), "systemic": True})
             for shape, mk in by_shape.items() if len(mk) >= 2]
    return sorted(edges, key=lambda e: e.key)


def write_edges(path: str | Path, edges: list[Edge]) -> None:
    """Write edges to a JSON file (sorted, deterministic).

    Args:
        path: Output file path.
        edges: List of edges to serialize.
    """
    Path(path).write_text(json.dumps([e.to_dict() for e in edges], indent=2))


_QUOTED = re.compile(r"['\"]([^'\"]{3,80})['\"]")


def _privilege_tokens(f: IngestedFinding) -> set[str]:
    """Extract candidate privilege/permission tokens from a finding (deterministic, no source).

    Tokens are quoted substrings in the message plus a permission-shaped ``rule_id`` (one that
    contains a space or a colon). Lowercased and stripped; short/empty tokens dropped.

    Args:
        f: The ingested finding.

    Returns:
        A set of privilege/permission token strings, lowercased, with length >= 3.
    """
    toks = {m.group(1).strip().lower() for m in _QUOTED.finditer(f.finding.message or "")}
    if f.finding.rule_id and (" " in f.finding.rule_id or ":" in f.finding.rule_id):
        toks.add(f.finding.rule_id.strip().lower())
    return {t for t in toks if len(t) >= 3}


def control_enforces_edges(ings: list[IngestedFinding]) -> list[Edge]:
    """Join a privilege token shared by an rbac-source finding and a service-enforcer finding.

    Args:
        ings: All ingested findings (each carries its member role).

    Returns:
        One ``control-enforces`` edge per token present in BOTH an ``rbac-source`` member finding
        and a ``service-enforcer`` member finding, sorted by key. ``join="deterministic"``.
    """
    rbac: dict[str, IngestedFinding] = {}
    svc: dict[str, IngestedFinding] = {}
    for i in ings:
        if i.role == "rbac-source":
            for t in _privilege_tokens(i):
                rbac.setdefault(t, i)
        elif i.role == "service-enforcer":
            for t in _privilege_tokens(i):
                svc.setdefault(t, i)
    edges = []
    for tok in sorted(set(rbac) & set(svc)):
        a, b = rbac[tok], svc[tok]
        edges.append(Edge(type="control-enforces", members=[a.member_key, b.member_key], key=tok,
                          detail={"join": "deterministic", "from": a.cross_repo_id,
                                  "to": b.cross_repo_id, "to_status": b.finding.status.value,
                                  "to_cls": b.finding.cls}))
    return edges
