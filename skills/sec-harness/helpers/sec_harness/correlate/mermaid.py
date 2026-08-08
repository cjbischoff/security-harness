"""Deterministic mermaid emitters from the cross-repo edge graph (code-authored, never LLM)."""

from __future__ import annotations

import re
from collections import defaultdict

from sec_harness.correlate.edges import Edge
from sec_harness.correlate.manifest import Manifest
from sec_harness.correlate.rethreshold import CorrelationVerdict

_UNSAFE = re.compile(r"[^0-9a-zA-Z]+")


def _node_id(s: str) -> str:
    """Return a mermaid-safe node id for a member key or cross-repo ref.

    Args:
        s: The raw identifier (member key, cross-repo id).

    Returns:
        The identifier with every run of non-alphanumeric characters collapsed to a single
        underscore and surrounding underscores stripped.
    """
    return _UNSAFE.sub("_", s).strip("_")


def component_graph(manifest: Manifest, edges: list[Edge]) -> str:
    """Emit a mermaid component graph: members grouped by role, joined by cross-repo edges.

    Members are grouped into a ``subgraph`` per role (roles sorted). ``control-enforces`` edges
    render as solid privilege-labeled arrows; ``shared-dependency`` edges render as dashed
    OSV-labeled links over each member pair. Output is deterministic (all lines sorted).

    Args:
        manifest: The product manifest (members + roles).
        edges: The cross-repo edges.

    Returns:
        A mermaid ``flowchart LR`` document as a string.
    """
    lines = ["flowchart LR"]
    by_role: dict[str, list[str]] = defaultdict(list)
    for m in manifest.members:
        by_role[m.role].append(m.member_key)
    for role in sorted(by_role):
        lines.append(f"  subgraph {role}")
        for mk in sorted(by_role[role]):
            lines.append(f'    {_node_id(mk)}["{mk}"]')
        lines.append("  end")
    links: list[str] = []
    for e in edges:
        mem = sorted(e.members)
        if len(mem) < 2:
            continue
        if e.type == "control-enforces":
            for i in range(len(mem) - 1):
                x, y = _node_id(mem[i]), _node_id(mem[i + 1])
                links.append(f"  {x} -->|{e.key}| {y}")
        elif e.type == "shared-dependency":
            for i in range(len(mem) - 1):
                x, y = _node_id(mem[i]), _node_id(mem[i + 1])
                links.append(f"  {x} -.->|{e.key}| {y}")
    lines.extend(sorted(set(links)))
    return "\n".join(lines) + "\n"


_STATUS_CLASS = {"confirmed": "confirmed", "rejected": "rejected"}
_CLASSDEFS = [
    "classDef confirmed fill:#f88;",
    "classDef rejected fill:#ccc;",
    "classDef ndt fill:#fc8;",
]


def attack_chain_graph(verdicts: list[CorrelationVerdict], edges: list[Edge]) -> str:
    """Emit a mermaid graph of cross-repo attack chains (source finding → resolving enforcer).

    One chain per verdict whose ``direction`` landed an edge (promote/weaken/demote); the sink is
    the resolving edge's ``detail["to"]`` — matched on the edge whose ``detail["from"]`` is the
    verdict's ``finding_ref`` (a unique anchor, so the sink is collision-free) — else the first
    evidence-chain entry, else the edge key. Each source node is classed by its
    ``correlated_status``. ``coverage-gap`` verdicts draw no chain. Output is deterministic
    (verdicts sorted by finding_ref; the edge index resolves ties by a sorted from/to key).

    Args:
        verdicts: All correlation verdicts.
        edges: All edges (used to resolve the sink for a verdict's source finding).

    Returns:
        A mermaid ``flowchart LR`` document as a string.
    """
    # index control-enforces sinks by their source anchor (detail["from"]), which equals the
    # re-thresholded finding's finding_ref; sorted + setdefault keeps it order-independent.
    to_by_from: dict[str, str] = {}
    for e in sorted(edges, key=lambda x: (x.detail.get("from", ""), x.detail.get("to", ""))):
        if e.type == "control-enforces":
            to_by_from.setdefault(e.detail.get("from", ""), e.detail.get("to", ""))
    lines = ["flowchart LR"]
    chains: list[str] = []
    node_class: dict[str, str] = {}
    for v in sorted(verdicts, key=lambda x: x.finding_ref):
        if v.direction not in ("promote", "weaken", "demote"):
            continue
        sink = to_by_from.get(v.finding_ref) or (
            v.evidence_chain[0] if v.evidence_chain else (v.edge or "sink"))
        src_id, sink_id = _node_id(v.finding_ref), _node_id(sink)
        chains.append(f"  {src_id} --> {sink_id}")
        node_class[src_id] = _STATUS_CLASS.get(v.correlated_status, "ndt")
    lines.extend(sorted(set(chains)))
    for nid in sorted(node_class):
        lines.append(f"  class {nid} {node_class[nid]}")
    lines.extend(f"  {d}" for d in _CLASSDEFS)
    return "\n".join(lines) + "\n"
