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

import argparse
import json
import re
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sec_harness import entrypoints, structural_index
from sec_harness.workspace import Workspace

NO_PATH_RECEIPT = "structural-index:no-path"

_SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java",
                ".c", ".cc", ".cpp", ".rb", ".php"}

# Call-edge detection helpers (see build_tier1). _CALL_TOKEN captures every
# \w-identifier used as a call in a body; _WORD_NAME selects names for which
# called-set membership is equivalent to the per-name \b<name>\s*\( regex.
_CALL_TOKEN = re.compile(r"\b(\w+)\s*\(")
_WORD_NAME = re.compile(r"\w+")


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
    """A directed relation between two nodes (``calls``/``imports``/``taint``).

    ``imports`` is reserved for forward compatibility; Tier-1/Tier-2 do not emit it today.
    """

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
        lang = _lang_of(rel)
        file_lines = path.read_text().splitlines()
        for name, line in structural_index.list_definitions(path):
            node_id = f"{rel}:{line}:{name}"
            start, end = structural_index.get_function_boundary(path, line)
            reason = entrypoints.classify_entry_point(lang, file_lines, start, end)
            attrs = {"lang": lang, "unresolvable": False, "is_entry_point": reason is not None}
            if reason is not None:
                attrs["entry_point_reason"] = reason
            nodes.append(Node(node_id, "symbol", rel, line, name, attrs))
            by_name.setdefault(name, []).append(node_id)
            bodies.append((node_id, str(path), start, end))

    # Call-edge detection. Equivalent to matching r"\b<name>\s*\(" against each
    # body for every known name, but without the O(bodies*names) fresh-regex
    # compile that dominated large repos. For purely-\w names, membership in the
    # body's called-token set (one finditer per body) is provably identical to
    # that per-name regex; odd names (e.g. JS "$foo") keep a precompiled pattern.
    word_names = {n for n in by_name if _WORD_NAME.fullmatch(n)}
    odd_patterns = {
        n: re.compile(r"\b" + re.escape(n) + r"\s*\(")
        for n in by_name if n not in word_names
    }
    edges: list[Edge] = []
    seen: set[tuple[str, str, str]] = set()
    for node_id, abspath, start, end in bodies:
        text = "\n".join(Path(abspath).read_text().splitlines()[start:end])
        called = {m.group(1) for m in _CALL_TOKEN.finditer(text)}
        for callee_name, targets in by_name.items():
            if callee_name in word_names:
                if callee_name not in called:
                    continue
            elif not odd_patterns[callee_name].search(text):
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


def entry_point_nodes(graph: Graph) -> list[Node]:
    """Return all nodes flagged as entry points during Tier-1 build.

    Args:
        graph: The substrate to query.

    Returns:
        Nodes whose ``attrs["is_entry_point"]`` is true, in graph node order.
    """
    return [n for n in graph.nodes if n.attrs.get("is_entry_point")]


def symbol_at(graph: Graph, file: str, line: int) -> str | None:
    """Return the name of the symbol enclosing ``file:line``, or ``None``.

    The enclosing symbol is the nearest ``symbol`` node in ``file`` whose definition
    line is at or before ``line``. Used to derive a refactor-resistant finding anchor
    (line-independent identity) from the Tier-1 substrate.

    Args:
        graph: The evidence substrate.
        file: Repo-relative path of the location.
        line: 1-indexed line number of the location.

    Returns:
        The enclosing symbol's ``name``, or ``None`` when no definition precedes it.
    """
    best: Node | None = None
    for n in graph.nodes:
        if n.kind == "symbol" and n.file == file and n.line <= line and (
            best is None or n.line > best.line
        ):
            best = n
    return best.name if best else None


@dataclass
class NoPathResult:
    """Result of a :func:`no_path` disproof query.

    Attributes:
        answer: True if no taint path connects source to sink.
        provable: True only when Tier-2 taint coverage exists for the sink's language.
        receipt: ``NO_PATH_RECEIPT`` when ``answer and provable``, else ``None``.
    """

    answer: bool
    provable: bool
    receipt: str | None


def no_path(graph: Graph, source: str, sink: str, *, max_depth: int = 12) -> NoPathResult:
    """Disprove a source->sink flow with a receipt, honestly gated on taint coverage.

    Traverses taint edges only. A ``NO_PATH_RECEIPT`` is minted ONLY when the sink's
    language has Tier-2 taint coverage (``graph.taint_langs``) and no taint path is
    found — because CodeQL/semgrep taint models the language's dataflow, its silence is
    meaningful, whereas absent Tier-1 heuristic edges prove nothing.

    Args:
        graph: The substrate (should be version 2 for a provable result).
        source: External-input source node id.
        sink: Sink node id.
        max_depth: Maximum taint-edge hops to traverse.

    Returns:
        A :class:`NoPathResult`; ``receipt`` is set only under the honesty gate.
    """
    sink_node = graph.node(sink)
    sink_lang = sink_node.attrs.get("lang", "") if sink_node else ""
    covered = sink_lang in graph.taint_langs
    path_exists = _bfs(_adjacency(graph, {"taint"}), source, sink, max_depth)
    answer = not path_exists
    provable = covered
    receipt = NO_PATH_RECEIPT if (answer and provable) else None
    return NoPathResult(answer=answer, provable=provable, receipt=receipt)


def _taint_receipt(sources: list[str]) -> bool:
    """True if any evidence source is a taint-dataflow receipt (codeql/semgrep)."""
    for s in sources:
        if s.startswith("codeql:") and "dataflow" in s:
            return True
        if s.startswith("semgrep:"):
            return True
    return False


def _ensure_node(graph: Graph, node_id: str, kind: str, file: str, line: int) -> None:
    """Add a node with ``node_id`` if the graph does not already contain it."""
    if graph.node(node_id) is None:
        graph.nodes.append(
            Node(node_id, kind, file, line, node_id.rsplit(":", 1)[-1],
                 {"lang": _lang_of(file), "unresolvable": False})
        )


def taint_sink_id(cand) -> str:
    """Return the canonical Tier-2 sink node id for a taint candidate.

    This is the SAME derivation :func:`merge_tier2` uses to mint the sink node. Any
    consumer (e.g. :func:`no_path`) that hand-derives this id instead of calling this
    helper risks a one-component drift that finds no taint edge and mints a false
    ``structural-index:no-path`` clean-disproof receipt for a finding with a real path.

    Args:
        cand: A prefilter candidate (``Finding``) with ``file``/``line``.

    Returns:
        The sink node id.
    """
    return f"{cand.file}:{cand.line}:{cand.file.rsplit('/', 1)[-1]}"


def taint_source_id(cand) -> str:
    """Return the canonical synthetic external-source node id for a taint candidate.

    Callers MUST use this (not a hand-derived string) to stay aligned with
    :func:`merge_tier2` — see :func:`taint_sink_id` for the false-disproof risk this
    shared derivation avoids.

    Args:
        cand: A prefilter candidate (``Finding``) with ``file``.

    Returns:
        The synthetic source node id.
    """
    return f"external:{cand.file}:0:external"


def merge_tier2(graph: Graph, candidates: list, taint_langs: list[str]) -> None:
    """Merge CodeQL/semgrep taint dataflow edges into the substrate (Tier-2).

    The taint edge is a single-hop external->sink abstraction: the frozen ``Finding``
    carries no dataflow source location, so it is sufficient for the ``no_path`` honesty
    gate but does not reconstruct multi-hop dataflow.

    Args:
        graph: The Tier-1 substrate to upgrade in place.
        candidates: Prefilter candidates (``Finding``); only those with a taint receipt
            contribute a taint edge.
        taint_langs: Languages CodeQL/semgrep taint actually ran for. Sets the honesty
            gate for :func:`no_path`.
    """
    for cand in candidates:
        sources = list(getattr(cand, "evidence_sources", []) or [])
        if not _taint_receipt(sources):
            continue
        sink_id = taint_sink_id(cand)
        src_id = taint_source_id(cand)
        _ensure_node(graph, sink_id, "sink", cand.file, cand.line)
        _ensure_node(graph, src_id, "source", cand.file, 0)
        graph.edges.append(Edge(src_id, sink_id, "taint"))

    graph.version = max(graph.version, 2)
    if "tier-2" not in graph.tiers:
        graph.tiers.append("tier-2")
    graph.taint_langs = sorted(set(graph.taint_langs) | set(taint_langs))


def build_and_write_tier1(
    ws,
    target_root: str | Path,
    sha: str,
    *,
    sca_fn=None,
    secrets_fn=None,
    crypto_fn=None,
) -> Path:
    """Build the Tier-1 substrate with facts attached and persist it.

    LLM-free convenience for the pre-recon orchestration step. Tool functions are
    injected (each returns a list of ``{"detail", "node_id"}`` dicts); a missing tool is
    represented by a no-op returning ``[]`` so the substrate still builds.

    Args:
        ws: Target workspace.
        target_root: Repo root to index.
        sha: Pinned commit sha.
        sca_fn: Callable ``(root) -> list[dict]`` of dependency facts.
        secrets_fn: Callable ``(root) -> list[dict]`` of secret facts.
        crypto_fn: Callable ``(root) -> list[dict]`` of crypto facts.

    Returns:
        The path to the written ``kb/graph.json``.
    """
    graph = build_tier1(target_root, sha)
    attach_facts(
        graph,
        dependencies=(sca_fn or (lambda _root: []))(target_root),
        secrets=(secrets_fn or (lambda _root: []))(target_root),
        crypto=(crypto_fn or (lambda _root: []))(target_root),
    )
    return save_graph(ws, graph)


def main(argv: list[str] | None = None) -> int:
    """CLI for the evidence substrate (build / query).

    Args:
        argv: Optional argument vector.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-graph")
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Build the Tier-1 substrate.")
    b.add_argument("--target", required=True)
    b.add_argument("--workspace", required=True)
    b.add_argument("--sha", required=True)

    q = sub.add_parser("query", help="Query the persisted substrate.")
    q.add_argument("--workspace", required=True)
    q.add_argument("--kind", required=True, choices=["reaches", "no-path"])
    q.add_argument("--src", required=True)
    q.add_argument("--dst", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "build":
        ws = Workspace(root=Path(args.workspace))
        ws.ensure()
        graph = build_tier1(args.target, args.sha)
        save_graph(ws, graph)
        print(f"nodes={len(graph.nodes)} edges={len(graph.edges)}")
        return 0
    if args.cmd == "query":
        ws = Workspace(root=Path(args.workspace))
        graph = load_graph(ws)
        if args.kind == "reaches":
            print(str(reaches(graph, args.src, args.dst)).lower())
        else:
            result = no_path(graph, args.src, args.dst)
            print(f"answer={str(result.answer).lower()} "
                  f"provable={str(result.provable).lower()} receipt={result.receipt}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
