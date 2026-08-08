"""Deterministic mermaid emitters from the cross-repo edge graph (code-authored, never LLM)."""

from __future__ import annotations

import re
from collections import defaultdict

from sec_harness.correlate.edges import Edge
from sec_harness.correlate.manifest import Manifest

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
