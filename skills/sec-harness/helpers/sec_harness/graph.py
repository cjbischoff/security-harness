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
import re
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sec_harness import structural_index

NO_PATH_RECEIPT = "structural-index:no-path"

_SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java",
                ".c", ".cc", ".cpp", ".rb", ".php"}


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


def _lang_of(path: str) -> str:
    """Return the language tag (extension without dot) for ``path``."""
    suffix = Path(path).suffix
    return suffix[1:] if suffix else ""


def build_tier1(target_root: str | Path, sha: str) -> Graph:
    """Assemble the Tier-1 substrate: definition nodes + one-hop call/import edges.

    LLM-free. Uses :mod:`sec_harness.structural_index` for definitions and a
    name-reference heuristic for call edges. Edges are approximate (heuristic, not
    compiler-grade) and used for positive corroboration and navigation only.

    Args:
        target_root: Repo root to index.
        sha: The pinned commit sha to stamp on the graph.

    Returns:
        A version-1 :class:`Graph` with ``tiers=["tier-1"]`` and no taint edges.
    """
    root = Path(target_root)
    nodes: list[Node] = []
    by_name: dict[str, list[str]] = {}
    bodies: list[tuple[str, str, int, int]] = []  # (node_id, file, start, end)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in _SOURCE_EXTS:
            continue
        rel = path.relative_to(root).as_posix()
        for name, line in structural_index.list_definitions(path):
            node_id = f"{rel}:{line}:{name}"
            nodes.append(Node(node_id, "symbol", rel, line, name,
                              {"lang": _lang_of(rel), "unresolvable": False}))
            by_name.setdefault(name, []).append(node_id)
            start, end = structural_index.get_function_boundary(path, line)
            bodies.append((node_id, str(path), start, end))

    edges: list[Edge] = []
    seen: set[tuple[str, str, str]] = set()
    for node_id, abspath, start, end in bodies:
        text = "\n".join(Path(abspath).read_text().splitlines()[start:end])
        for callee_name, targets in by_name.items():
            if not re.search(r"\b" + re.escape(callee_name) + r"\s*\(", text):
                continue
            for dst in targets:
                if dst == node_id:
                    continue
                key = (node_id, dst, "calls")
                if key not in seen:
                    seen.add(key)
                    edges.append(Edge(node_id, dst, "calls"))

    return Graph(1, sha, ["tier-1"], [], nodes, edges, [])


def attach_facts(
    graph: Graph,
    *,
    dependencies: list[dict] | None = None,
    secrets: list[dict] | None = None,
    crypto: list[dict] | None = None,
) -> None:
    """Attach dependency/secret/crypto facts to ``graph`` in place.

    Args:
        graph: The substrate to enrich.
        dependencies: ``{"detail", "node_id"}`` dicts from the SCA/OSV scan.
        secrets: ``{"detail", "node_id"}`` dicts from the secrets scan.
        crypto: ``{"detail", "node_id"}`` dicts from the crypto-policy check.
    """
    for kind, source, rows in (
        ("dependency", "sca", dependencies or []),
        ("secret", "secrets", secrets or []),
        ("crypto", "crypto-policy", crypto or []),
    ):
        for row in rows:
            graph.facts.append(
                Fact(kind, row["detail"], source, row.get("node_id"))
            )


_TRAVERSABLE = {"calls", "imports", "taint"}


def _adjacency(graph: Graph, kinds: set[str]) -> dict[str, list[str]]:
    """Build a src -> [dst] map over edges whose kind is in ``kinds``."""
    adj: dict[str, list[str]] = {}
    for e in graph.edges:
        if e.kind in kinds:
            adj.setdefault(e.src, []).append(e.dst)
    return adj


def _bfs(adj: dict[str, list[str]], src: str, dst: str, max_depth: int) -> bool:
    """Return True if ``dst`` is reachable from ``src`` within ``max_depth`` hops."""
    if src == dst:
        return True
    queue: deque[tuple[str, int]] = deque([(src, 0)])
    seen = {src}
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for nxt in adj.get(node, []):
            if nxt == dst:
                return True
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, depth + 1))
    return False


def reaches(graph: Graph, src: str, dst: str, *, max_depth: int = 12) -> bool:
    """True if ``dst`` is reachable from ``src`` over call/import/taint edges.

    Positive corroboration only: heuristic Tier-1 edges are incomplete, so a False
    result is NOT proof of unreachability — use :func:`no_path` for a disproof receipt.

    Args:
        graph: The substrate.
        src: Source node id.
        dst: Target node id.
        max_depth: Maximum edge hops to traverse.

    Returns:
        Whether a path exists within the depth bound.
    """
    return _bfs(_adjacency(graph, _TRAVERSABLE), src, dst, max_depth)


def attacker_controls(graph: Graph, source: str, node: str, *, max_depth: int = 12) -> bool:
    """True if an external-input ``source`` node reaches ``node`` (attacker-control).

    Args:
        graph: The substrate.
        source: An external-input source node id.
        node: The node whose attacker-control is in question.
        max_depth: Maximum edge hops to traverse.

    Returns:
        Whether the source reaches the node.
    """
    return reaches(graph, source, node, max_depth=max_depth)


def is_unresolvable(graph: Graph, node_id: str) -> bool:
    """True if ``node_id`` is flagged dynamic/reflective/config-wired (route to runtime)."""
    n = graph.node(node_id)
    return bool(n and n.attrs.get("unresolvable", False))
