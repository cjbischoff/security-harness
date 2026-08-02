"""Shared evidence substrate: a persisted, deterministic code graph.

Structural facts an audit re-derives at multiple phases — can untrusted input reach a
sink, does an attacker control it, is there provably no path — are computed once into
``kb/graph.json`` and queried everywhere, including to disprove a finding with a receipt.

Two tiers. Tier-1 (LLM-free, pre-recon) holds definition nodes plus one-hop call/import
edges and dependency/secret/crypto facts; it grounds positive corroboration and
navigation only. Tier-2 (post-prefilter) merges CodeQL/semgrep taint dataflow edges. The
``no_path`` disproof receipt is mintable only under Tier-2 taint coverage (see
:func:`no_path`).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

NO_PATH_RECEIPT = "structural-index:no-path"


@dataclass
class Node:
    """A code node in the substrate (a definition, entrypoint, sink, or control)."""

    id: str
    kind: str
    file: str
    line: int
    name: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    """A directed relation between two nodes (``calls``/``imports``/``taint``)."""

    src: str
    dst: str
    kind: str


@dataclass
class Fact:
    """A non-structural finding attached to the graph (dependency/secret/crypto)."""

    kind: str
    detail: str
    source: str
    node_id: str | None = None


@dataclass
class Graph:
    """The persisted evidence substrate for one campaign pass."""

    version: int
    sha: str
    tiers: list[str]
    taint_langs: list[str]
    nodes: list[Node]
    edges: list[Edge]
    facts: list[Fact]

    def node(self, node_id: str) -> Node | None:
        """Return the node with ``node_id`` or ``None``."""
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def to_dict(self) -> dict:
        """Serialize to a JSON-ready dict."""
        return {
            "version": self.version,
            "sha": self.sha,
            "tiers": list(self.tiers),
            "taint_langs": list(self.taint_langs),
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
            "facts": [asdict(f) for f in self.facts],
        }

    @classmethod
    def from_dict(cls, d: dict) -> Graph:
        """Rebuild a :class:`Graph` from :meth:`to_dict` output."""
        return cls(
            version=d["version"],
            sha=d["sha"],
            tiers=list(d.get("tiers", [])),
            taint_langs=list(d.get("taint_langs", [])),
            nodes=[Node(**n) for n in d.get("nodes", [])],
            edges=[Edge(**e) for e in d.get("edges", [])],
            facts=[Fact(**f) for f in d.get("facts", [])],
        )


def save_graph(ws, graph: Graph) -> Path:
    """Write the substrate to ``kb/graph.json`` and return the path.

    Args:
        ws: Target :class:`sec_harness.workspace.Workspace`.
        graph: The substrate to persist.

    Returns:
        The path written.
    """
    ws.kb.mkdir(parents=True, exist_ok=True)
    path = ws.kb / "graph.json"
    path.write_text(json.dumps(graph.to_dict(), indent=2))
    return path


def load_graph(ws) -> Graph:
    """Load the substrate from ``kb/graph.json``.

    Args:
        ws: Source :class:`sec_harness.workspace.Workspace`.

    Returns:
        The parsed :class:`Graph`.
    """
    return Graph.from_dict(json.loads((ws.kb / "graph.json").read_text()))
