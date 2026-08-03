# Evidence Substrate (kb/graph.json) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a persisted, deterministic shared evidence substrate (`kb/graph.json`) that computes structural facts once and exposes a small query API (`reaches`, `attacker_controls`, `no_path`, `is_unresolvable`) reused by every phase — including as a receipt-backed disproof of findings.

**Architecture:** A new stdlib-only module `sec_harness/graph.py` assembles nodes/edges/facts from existing modules (`structural_index`, `ast-grep` via `astgrep`, `osv`/`sca`, `secrets`, `crypto_policy`) into a JSON document with two tiers. Tier-1 (LLM-free, pre-recon) persists code nodes plus one-hop call/import edges and dependency/secret/crypto facts — used for **positive corroboration and navigation only**. Tier-2 (post-prefilter) merges CodeQL/semgrep taint dataflow edges. The `no_path` disproof receipt (`structural-index:no-path`) is mintable **only** when Tier-2 taint coverage exists for the sink's language — never from Tier-1 heuristic edges.

**Tech Stack:** Python 3.13, stdlib only (`json`, `subprocess`, `pathlib`, `dataclasses`, `re`, `argparse`). Tests: `pytest`. Lint: `ruff` (line-length 100). Types: `ty`.

## Global Constraints

- **Git boundary:** touch ONLY files under `skills/sec-harness/`. Never edit/stage/commit anything under `go/`. Never `git add -A` / `git add .` / `git commit -a` — stage explicit paths and run `git status` before every commit to confirm no `go/` path is staged.
- **Branch:** work on `skill-artifact-substrate-20260802`. Never commit to `main`.
- **Frozen JSON contract is untouchable:** do NOT modify `helpers/sec_harness/models.py` or `helpers/sec_harness/evidence.py`. The receipt string `structural-index:no-path` is already accepted by `evidence.is_tool_receipt` (`structural-index` ∈ `_MECHANICAL`, `evidence.py:14`) — reuse it, do not add a new receipt source.
- **Core is stdlib-only:** no new runtime dependencies in `pyproject.toml`. Dev deps stay pytest/ruff/ty.
- **Honesty gate (Decision 1 = B):** `no_path` returns a mintable receipt ONLY when Tier-2 taint edges cover the sink's language. Tier-1 alone can never assert no-path — absence of a heuristic call-edge is not proof of no dataflow.
- **Style:** every module/public function gets a Google-style docstring. `from __future__ import annotations` at the top of each new module. Line length ≤100. `uv run ruff check` and `uv run ty check` clean before every commit.
- **All commands run from** `skills/sec-harness/helpers/`.

---

## File Structure

- Create: `sec_harness/graph.py` — substrate model, Tier-1 build, fact attachment, Tier-2 merge, query API, CLI. One responsibility: the evidence substrate.
- Create: `tests/test_graph.py` — unit tests for model round-trip, build, facts, queries, Tier-2 merge, CLI.
- Create: `tests/fixtures/graph_target/` — a tiny fixture repo (a source→sink call chain in Python) the build/query tests run against.
- Modify (doc only): `SKILL.md`, `CLAUDE.md` — add the Tier-1 pre-recon pass to the phase list.

The substrate is intentionally one module. It is small, changes together, and is easier to hold in context as a unit than split across model/build/query files.

---

## Data Contract (the `kb/graph.json` document)

Defined in Task 1; every later task depends on these exact shapes.

```json
{
  "version": 1,
  "sha": "<pinned commit sha>",
  "tiers": ["tier-1"],
  "taint_langs": [],
  "nodes": [
    {"id": "app/db.py:12:run_query", "kind": "symbol",
     "file": "app/db.py", "line": 12, "name": "run_query",
     "attrs": {"lang": "py", "unresolvable": false}}
  ],
  "edges": [
    {"src": "app/api.py:5:handler", "dst": "app/db.py:12:run_query", "kind": "calls"}
  ],
  "facts": [
    {"kind": "dependency", "detail": "requests==2.0.0 CVE-2018-...",
     "source": "sca", "node_id": null}
  ]
}
```

- `kind` on a node ∈ `{"symbol", "entrypoint", "sink", "source", "component", "control"}`. Tier-1 emits `symbol` for every definition; richer kinds are set by Plan 2 artifact phases.
- `kind` on an edge ∈ `{"calls", "imports", "taint"}`. `taint` edges appear only after Tier-2 merge.
- `source` on a fact is the receipt namespace: `"sca"`, `"secrets"`, or `"crypto-policy"` (data, not asserted as a `_MECHANICAL` receipt).
- `taint_langs` lists languages for which Tier-2 taint ran; it gates `no_path` provability.
- Node id is stable: `f"{file}:{line}:{name}"`.

---

### Task 1: Substrate model + load/save round-trip

**Files:**
- Create: `sec_harness/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: nothing (foundation).
- Produces:
  - `Node(id: str, kind: str, file: str, line: int, name: str, attrs: dict)` (dataclass)
  - `Edge(src: str, dst: str, kind: str)` (dataclass)
  - `Fact(kind: str, detail: str, source: str, node_id: str | None = None)` (dataclass)
  - `Graph(version: int, sha: str, tiers: list[str], taint_langs: list[str], nodes: list[Node], edges: list[Edge], facts: list[Fact])` (dataclass) with methods `node(node_id: str) -> Node | None`, `to_dict() -> dict`, and classmethod `from_dict(d: dict) -> Graph`.
  - `save_graph(ws, graph: Graph) -> Path` — writes `ws.kb / "graph.json"`.
  - `load_graph(ws) -> Graph` — reads `ws.kb / "graph.json"`.
  - Module constant `NO_PATH_RECEIPT = "structural-index:no-path"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph.py
from pathlib import Path

from sec_harness import graph as g
from sec_harness.workspace import Workspace


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path / "ws")
    ws.ensure()
    return ws


def test_graph_roundtrips_through_dict():
    graph = g.Graph(
        version=1, sha="abc123", tiers=["tier-1"], taint_langs=[],
        nodes=[g.Node("a.py:1:f", "symbol", "a.py", 1, "f", {"lang": "py"})],
        edges=[g.Edge("a.py:1:f", "b.py:2:h", "calls")],
        facts=[g.Fact("secret", "aws key at c.py:3", "secrets", "c.py:3:k")],
    )
    restored = g.Graph.from_dict(graph.to_dict())
    assert restored == graph
    assert restored.node("a.py:1:f").name == "f"
    assert restored.node("missing") is None


def test_save_and_load_graph(tmp_path):
    ws = _ws(tmp_path)
    graph = g.Graph(1, "sha1", ["tier-1"], [], [], [], [])
    path = g.save_graph(ws, graph)
    assert path == ws.kb / "graph.json"
    assert g.load_graph(ws) == graph
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -v`
Expected: FAIL with `ModuleNotFoundError: sec_harness.graph` / `AttributeError`.

- [ ] **Step 3: Write minimal implementation**

```python
# sec_harness/graph.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS (both tests).

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check sec_harness/graph.py tests/test_graph.py
uv run ty check
git add skills/sec-harness/helpers/sec_harness/graph.py skills/sec-harness/helpers/tests/test_graph.py
git status   # confirm ONLY skills/ paths staged
git commit -m "feat(graph): substrate model + load/save"
```

---

### Task 2: Tier-1 build — nodes + one-hop call/import edges

**Files:**
- Modify: `sec_harness/graph.py`
- Create: `tests/fixtures/graph_target/app/api.py`, `tests/fixtures/graph_target/app/db.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `structural_index.list_definitions(path)`, `Node`/`Edge`/`Graph` from Task 1.
- Produces:
  - `build_tier1(target_root: str | Path, sha: str) -> Graph` — walks the repo, emits one `symbol` node per definition (id `f"{relpath}:{line}:{name}"`, `attrs={"lang": <ext>, "unresolvable": False}`) and `calls`/`imports` edges where a definition's body references another indexed symbol by name. Version 1, `tiers=["tier-1"]`, `taint_langs=[]`, `facts=[]`.
  - `_lang_of(path: str) -> str` — file extension without the dot (`"py"`, `"ts"`, …), `""` if none.

The fixture is a deliberate source→sink chain so later query tests have a known path:

```python
# tests/fixtures/graph_target/app/api.py
from app.db import run_query


def handler(request):
    user_input = request.args.get("q")
    return run_query(user_input)
```

```python
# tests/fixtures/graph_target/app/db.py
def run_query(sql):
    cursor.execute(sql)
    return cursor.fetchall()
```

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_graph.py
FIXTURE = Path(__file__).parent / "fixtures" / "graph_target"


def test_build_tier1_emits_nodes_and_call_edge():
    graph = g.build_tier1(FIXTURE, sha="deadbeef")
    assert graph.version == 1
    assert graph.tiers == ["tier-1"]
    ids = {n.id for n in graph.nodes}
    assert "app/api.py:4:handler" in ids
    assert "app/db.py:1:run_query" in ids
    assert graph.node("app/api.py:4:handler").attrs["lang"] == "py"
    # handler() calls run_query() -> a call edge exists between the two nodes
    assert any(
        e.kind == "calls"
        and e.src == "app/api.py:4:handler"
        and e.dst == "app/db.py:1:run_query"
        for e in graph.edges
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py::test_build_tier1_emits_nodes_and_call_edge -v`
Expected: FAIL with `AttributeError: module 'sec_harness.graph' has no attribute 'build_tier1'`.

- [ ] **Step 3: Write minimal implementation**

```python
# add to sec_harness/graph.py
import re
from sec_harness import structural_index

_SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java",
                ".c", ".cc", ".cpp", ".rb", ".php"}


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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS (all tests).

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check sec_harness/graph.py tests/test_graph.py
uv run ty check
git add skills/sec-harness/helpers/sec_harness/graph.py \
        skills/sec-harness/helpers/tests/test_graph.py \
        skills/sec-harness/helpers/tests/fixtures/graph_target
git status
git commit -m "feat(graph): tier-1 build (nodes + call edges)"
```

---

### Task 3: Fact attachment (osv / secrets / crypto)

**Files:**
- Modify: `sec_harness/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `Graph`, `Fact` from Task 1.
- Produces:
  - `attach_facts(graph: Graph, *, dependencies: list[dict] | None = None, secrets: list[dict] | None = None, crypto: list[dict] | None = None) -> None` — appends `Fact` entries to `graph.facts` in place. Each input dict is `{"detail": str, "node_id": str | None}`. Sources are set to `"sca"`, `"secrets"`, `"crypto-policy"` respectively.

Tool outputs are passed in (dependency-injected) so this is unit-testable without invoking `osv-scanner`/secrets scanning — those are slow external boundaries wired by the orchestration convenience in Task 8.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_graph.py
def test_attach_facts_tags_sources():
    graph = g.Graph(1, "s", ["tier-1"], [], [], [], [])
    g.attach_facts(
        graph,
        dependencies=[{"detail": "requests==2.0 CVE-x", "node_id": None}],
        secrets=[{"detail": "aws key", "node_id": "a.py:3:k"}],
        crypto=[{"detail": "md5 usage", "node_id": "b.py:9:hash"}],
    )
    by_source = {f.source: f for f in graph.facts}
    assert by_source["sca"].kind == "dependency"
    assert by_source["secrets"].node_id == "a.py:3:k"
    assert by_source["crypto-policy"].detail == "md5 usage"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py::test_attach_facts_tags_sources -v`
Expected: FAIL with `AttributeError: ... has no attribute 'attach_facts'`.

- [ ] **Step 3: Write minimal implementation**

```python
# add to sec_harness/graph.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check sec_harness/graph.py tests/test_graph.py
uv run ty check
git add skills/sec-harness/helpers/sec_harness/graph.py skills/sec-harness/helpers/tests/test_graph.py
git status
git commit -m "feat(graph): attach dependency/secret/crypto facts"
```

---

### Task 4: Query API — reaches, attacker_controls, is_unresolvable

**Files:**
- Modify: `sec_harness/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `Graph`, `Edge` from Task 1; the fixture build from Task 2.
- Produces:
  - `reaches(graph: Graph, src: str, dst: str, *, max_depth: int = 12) -> bool` — BFS over `calls`/`imports`/`taint` edges from `src`; True if `dst` is reachable within `max_depth` hops. Positive corroboration only.
  - `attacker_controls(graph: Graph, source: str, node: str, *, max_depth: int = 12) -> bool` — thin alias of `reaches(graph, source, node, max_depth=max_depth)` documenting attacker-control intent (source is an external-input node).
  - `is_unresolvable(graph: Graph, node_id: str) -> bool` — returns `graph.node(node_id).attrs.get("unresolvable", False)`; missing node → `False`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_graph.py
def test_reaches_finds_transitive_path():
    graph = g.build_tier1(FIXTURE, sha="x")
    assert g.reaches(graph, "app/api.py:4:handler", "app/db.py:1:run_query")
    # no reverse path
    assert not g.reaches(graph, "app/db.py:1:run_query", "app/api.py:4:handler")


def test_attacker_controls_is_reaches():
    graph = g.build_tier1(FIXTURE, sha="x")
    assert g.attacker_controls(graph, "app/api.py:4:handler", "app/db.py:1:run_query")


def test_reaches_respects_depth_cap():
    graph = g.Graph(1, "s", ["tier-1"], [], [
        g.Node("a", "symbol", "a", 1, "a", {}),
        g.Node("b", "symbol", "b", 1, "b", {}),
        g.Node("c", "symbol", "c", 1, "c", {}),
    ], [g.Edge("a", "b", "calls"), g.Edge("b", "c", "calls")], [])
    assert g.reaches(graph, "a", "c", max_depth=2)
    assert not g.reaches(graph, "a", "c", max_depth=1)


def test_is_unresolvable():
    graph = g.Graph(1, "s", ["tier-1"], [], [
        g.Node("a", "symbol", "a", 1, "a", {"unresolvable": True}),
        g.Node("b", "symbol", "b", 1, "b", {}),
    ], [], [])
    assert g.is_unresolvable(graph, "a")
    assert not g.is_unresolvable(graph, "b")
    assert not g.is_unresolvable(graph, "missing")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -k "reaches or attacker or unresolvable" -v`
Expected: FAIL with `AttributeError: ... has no attribute 'reaches'`.

- [ ] **Step 3: Write minimal implementation**

```python
# add to sec_harness/graph.py
from collections import deque

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check sec_harness/graph.py tests/test_graph.py
uv run ty check
git add skills/sec-harness/helpers/sec_harness/graph.py skills/sec-harness/helpers/tests/test_graph.py
git status
git commit -m "feat(graph): reaches/attacker_controls/is_unresolvable queries"
```

---

### Task 5: `no_path` disproof with the Tier-2 honesty gate

**Files:**
- Modify: `sec_harness/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `Graph`, `Node`, `Edge`, `NO_PATH_RECEIPT`, `_adjacency`/`_bfs` from prior tasks.
- Produces:
  - `NoPathResult(answer: bool, provable: bool, receipt: str | None)` (dataclass).
  - `no_path(graph: Graph, source: str, sink: str, *, max_depth: int = 12) -> NoPathResult` — traverses **taint edges only**. `provable` is True only when the sink node's `lang` is in `graph.taint_langs` (i.e. Tier-2 taint ran for that language). When `provable and answer` (no taint path found under coverage), `receipt = NO_PATH_RECEIPT`; otherwise `receipt = None`.

**Invariant (the honesty gate):** a `no_path` receipt is minted *only* when (a) taint coverage exists for the sink's language AND (b) no taint-edge path connects source→sink. Absence of Tier-1 heuristic edges never produces a receipt.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_graph.py
def _taint_graph(taint_langs, edges):
    nodes = [
        g.Node("src", "source", "a.py", 1, "src", {"lang": "py"}),
        g.Node("sink", "sink", "b.py", 1, "sink", {"lang": "py"}),
    ]
    return g.Graph(2, "s", ["tier-1", "tier-2"], taint_langs, nodes, edges, [])


def test_no_path_unprovable_without_taint_coverage():
    # Tier-1 only: python not in taint_langs -> cannot mint a receipt
    graph = _taint_graph([], [])
    result = g.no_path(graph, "src", "sink")
    assert result.provable is False
    assert result.receipt is None


def test_no_path_provable_and_clean_under_coverage():
    # taint ran for py, and there is no taint edge src->sink -> receipt minted
    graph = _taint_graph(["py"], [])
    result = g.no_path(graph, "src", "sink")
    assert result.answer is True
    assert result.provable is True
    assert result.receipt == g.NO_PATH_RECEIPT


def test_no_path_finds_taint_path_under_coverage():
    # taint ran for py and a taint edge connects src->sink -> path exists, no receipt
    graph = _taint_graph(["py"], [g.Edge("src", "sink", "taint")])
    result = g.no_path(graph, "src", "sink")
    assert result.answer is False
    assert result.provable is True
    assert result.receipt is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -k no_path -v`
Expected: FAIL with `AttributeError: ... has no attribute 'no_path'`.

- [ ] **Step 3: Write minimal implementation**

```python
# add to sec_harness/graph.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check sec_harness/graph.py tests/test_graph.py
uv run ty check
git add skills/sec-harness/helpers/sec_harness/graph.py skills/sec-harness/helpers/tests/test_graph.py
git status
git commit -m "feat(graph): no_path disproof gated on tier-2 taint coverage"
```

---

### Task 6: Tier-2 merge — ingest taint edges from a prefilter result

**Files:**
- Modify: `sec_harness/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `Graph`, `Edge`, `Node`; the prefilter result dict shape (`run_prefilter` returns `{"candidates": [...], "backends_run": [...], ...}` — `prefilter.py:73`). Each candidate is a `Finding` with `.file`, `.line`, `.evidence_sources`, and (optionally) `.source_file`/`.source_line` when a dataflow source is known.
- Produces:
  - `merge_tier2(graph: Graph, candidates: list, taint_langs: list[str]) -> None` — in place: for each candidate whose `evidence_sources` contains a taint receipt (`codeql:dataflow` or a `semgrep:` source), add a `taint` `Edge` from the candidate's source node to its sink node (creating `source`/`sink` `Node`s if absent), bump `graph.version` to 2, add `"tier-2"` to `graph.tiers`, and set `graph.taint_langs` to the given languages (deduped, sorted).
  - Helper `_taint_receipt(sources: list[str]) -> bool` — True if any source starts with `"codeql:"` containing `dataflow`, or `"semgrep:"`.

The caller (Task 8 orchestration) passes `taint_langs` = the languages CodeQL/semgrep taint actually ran for (derived from `backends_run` + the scan profile). Passing it explicitly keeps the honesty gate truthful.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_graph.py
from sec_harness.models import Finding, Severity, FindingStatus


def _candidate(**kw):
    base = dict(id="F-1", title="t", severity=Severity.HIGH,
                status=FindingStatus.CANDIDATE, file="b.py", line=1,
                evidence_sources=["codeql:dataflow"])
    base.update(kw)
    return Finding(**base)


def test_merge_tier2_adds_taint_edge_and_bumps_version():
    graph = g.build_tier1(FIXTURE, sha="x")
    cand = _candidate(file="app/db.py", line=1,
                      attrs={"source_file": "app/api.py", "source_line": 4})
    g.merge_tier2(graph, [cand], taint_langs=["py"])
    assert graph.version == 2
    assert "tier-2" in graph.tiers
    assert graph.taint_langs == ["py"]
    assert any(e.kind == "taint" for e in graph.edges)


def test_merge_tier2_ignores_non_taint_candidates():
    graph = g.build_tier1(FIXTURE, sha="x")
    cand = _candidate(evidence_sources=["llm-claimed:sqli"])
    g.merge_tier2(graph, [cand], taint_langs=["py"])
    assert not any(e.kind == "taint" for e in graph.edges)
```

Note: this test assumes `Finding` accepts an `attrs`/source-location field. If the frozen `Finding` model has no place for a dataflow source location, `merge_tier2` must derive the source node from the candidate's own `file:line` only (sink) and connect from a synthetic `external:*` source node. **Before implementing, read `helpers/sec_harness/models.py` to confirm the available `Finding` fields — do NOT add a field to the frozen model.** Adjust the test's `_candidate` and the implementation to use only fields that already exist (candidate exposes at least `file`, `line`, `evidence_sources`).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -k merge_tier2 -v`
Expected: FAIL with `AttributeError: ... has no attribute 'merge_tier2'`.

- [ ] **Step 3: Write minimal implementation**

```python
# add to sec_harness/graph.py
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


def merge_tier2(graph: Graph, candidates: list, taint_langs: list[str]) -> None:
    """Merge CodeQL/semgrep taint dataflow edges into the substrate (Tier-2).

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
        sink_id = f"{cand.file}:{cand.line}:{cand.file.rsplit('/', 1)[-1]}"
        src_file = f"external:{cand.file}"
        src_id = f"{src_file}:0:external"
        _ensure_node(graph, sink_id, "sink", cand.file, cand.line)
        _ensure_node(graph, src_id, "source", cand.file, 0)
        graph.edges.append(Edge(src_id, sink_id, "taint"))

    if graph.version < 2:
        graph.version = 2
    if "tier-2" not in graph.tiers:
        graph.tiers.append("tier-2")
    graph.taint_langs = sorted(set(graph.taint_langs) | set(taint_langs))
```

Adapt `sink_id`/`src_id` derivation to the real `Finding` fields confirmed in Step 1. The invariant to preserve: a taint edge's sink node carries the sink file's `lang`, and `taint_langs` reflects the languages taint truly covered.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check sec_harness/graph.py tests/test_graph.py
uv run ty check
git add skills/sec-harness/helpers/sec_harness/graph.py skills/sec-harness/helpers/tests/test_graph.py
git status
git commit -m "feat(graph): tier-2 taint-edge merge from prefilter candidates"
```

---

### Task 7: CLI — `python -m sec_harness.graph build|query`

**Files:**
- Modify: `sec_harness/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `build_tier1`, `save_graph`, `load_graph`, `reaches`, `no_path`, `Workspace`.
- Produces:
  - `main(argv: list[str] | None = None) -> int` with subcommands:
    - `build --target <root> --workspace <ws> --sha <sha>` → runs `build_tier1`, `save_graph`, prints node/edge counts, returns 0.
    - `query --workspace <ws> --kind reaches|no-path --src <id> --dst <id>` → loads the graph, prints the boolean/receipt, returns 0.
  - `if __name__ == "__main__": raise SystemExit(main())`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_graph.py
def test_cli_build_writes_graph(tmp_path):
    ws_root = tmp_path / "ws"
    rc = g.main(["build", "--target", str(FIXTURE),
                 "--workspace", str(ws_root), "--sha", "cafe"])
    assert rc == 0
    assert (ws_root / "kb" / "graph.json").exists()


def test_cli_query_reaches(tmp_path, capsys):
    ws_root = tmp_path / "ws"
    g.main(["build", "--target", str(FIXTURE),
            "--workspace", str(ws_root), "--sha", "cafe"])
    rc = g.main(["query", "--workspace", str(ws_root), "--kind", "reaches",
                 "--src", "app/api.py:4:handler", "--dst", "app/db.py:1:run_query"])
    assert rc == 0
    assert "true" in capsys.readouterr().out.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -k cli -v`
Expected: FAIL with `AttributeError: ... has no attribute 'main'`.

- [ ] **Step 3: Write minimal implementation**

```python
# add to sec_harness/graph.py
import argparse
from sec_harness.workspace import Workspace


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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS (all tests). Also verify the module runs as a CLI:
`uv run python -m sec_harness.graph build --target tests/fixtures/graph_target --workspace /tmp/graph-ws --sha cafe`

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check sec_harness/graph.py tests/test_graph.py
uv run ty check
git add skills/sec-harness/helpers/sec_harness/graph.py skills/sec-harness/helpers/tests/test_graph.py
git status
git commit -m "feat(graph): build/query CLI"
```

---

### Task 8: Orchestration convenience + phase-list documentation

**Files:**
- Modify: `sec_harness/graph.py` (add `build_and_write_tier1`)
- Modify: `SKILL.md` (phase list), `CLAUDE.md` (§3 phase order)
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `build_tier1`, `attach_facts`, `save_graph`; the existing tool functions `sca.scan`, `secrets` scan, `crypto_policy.check` (read their real signatures before wiring — do not assume). If a tool binary is unavailable, its facts are skipped (empty list), matching the harness's degrade-and-log behavior.
- Produces:
  - `build_and_write_tier1(ws, target_root: str | Path, sha: str, *, sca_fn=None, secrets_fn=None, crypto_fn=None) -> Path` — builds Tier-1, attaches whatever facts the injected tool fns return (each defaulting to a no-op returning `[]`), writes `kb/graph.json`, returns the path. Tool fns are injected so the unit test needs no external binaries.

**Documentation invariant:** the phase list must show the Tier-1 pass as a NEW, LLM-free deterministic step **before** recon (Decision 3), emitting `kb/graph.json` v1, consumed by recon/architecture/threat-model. Do not alter the frozen-contract note or the git-boundary section.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_graph.py
def test_build_and_write_tier1_attaches_injected_facts(tmp_path):
    ws = _ws(tmp_path)
    path = g.build_and_write_tier1(
        ws, FIXTURE, sha="x",
        sca_fn=lambda root: [{"detail": "dep CVE", "node_id": None}],
        secrets_fn=lambda root: [],
        crypto_fn=lambda root: [{"detail": "md5", "node_id": None}],
    )
    assert path == ws.kb / "graph.json"
    loaded = g.load_graph(ws)
    sources = {f.source for f in loaded.facts}
    assert "sca" in sources and "crypto-policy" in sources
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -k build_and_write -v`
Expected: FAIL with `AttributeError: ... has no attribute 'build_and_write_tier1'`.

- [ ] **Step 3: Write minimal implementation**

```python
# add to sec_harness/graph.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v`
Expected: PASS (full file green).

- [ ] **Step 5: Update the phase-list docs**

In `SKILL.md` and `CLAUDE.md` §3 (the "Phase order (one pass)" block), add a line immediately before recon:

```
T1 Tier-1 substrate  python -m sec_harness.graph build --target <T> --workspace <WS> --sha <sha>
                     # LLM-free: structural_index + ast-grep nodes/edges + osv/secrets/crypto facts
                     # → kb/graph.json v1 (consumed by recon, architecture, threat-model)
```

Add one sentence to the "Hard operating rules" noting: *the Tier-1 substrate is always built (never behind a flag); `no_path` receipts are only valid after Tier-2 taint merge at prefilter.* Do not touch the git-boundary or frozen-contract sections.

- [ ] **Step 6: Run the full suite, lint, type-check, commit**

```bash
uv run pytest -q          # expect the 3 known env-only failures only (see CLAUDE.md §2)
uv run ruff check sec_harness/graph.py tests/test_graph.py
uv run ty check
git add skills/sec-harness/helpers/sec_harness/graph.py \
        skills/sec-harness/helpers/tests/test_graph.py \
        skills/sec-harness/SKILL.md skills/sec-harness/CLAUDE.md
git status
git commit -m "feat(graph): tier-1 orchestration convenience + phase-list docs"
```

---

## Self-Review (completed against the spec)

**Spec coverage (this plan):**
- §3 substrate assembled from existing modules → Tasks 1–3, 6, 8. ✅
- §3 two-tier build (Tier-1 pre-recon, Tier-2 at prefilter) → Tasks 2/8 (Tier-1), Task 6 (Tier-2). ✅
- §3 query surface `reaches` / `attacker_controls` / `no_path` / `unresolvable` → Tasks 4–5. `control_covers` / `in_attack_surface` deferred to Plan 2 (they need artifact-produced control/entrypoint nodes). ✅ (documented deferral, not a gap)
- §6 disproof receipt (`structural-index:no-path`) with the honesty gate → Task 5. ✅
- Decision 1 (B, incremental; no_path gated on Tier-2) → Task 5 invariant. ✅
- Decision 3 (Tier-1 as a separate pre-recon pass) → Task 8 docs. ✅
- Decision 4 (substrate always on) → Task 8 hard-rule note. ✅

**Deferred to follow-on plans (not gaps — sequenced):**
- Plan 2 — Deliverable artifacts: `sec-design.md` (C4), `attack-tree.md`, `attack-surface.md`, richer `THREAT_MODEL.md` sub-models; new gate extractors (`claims_from_secdesign`, etc.); the `--no-deliverables` opt-out flag (Decision 4); `control_covers`/`in_attack_surface` queries; Decision 2 (attack-tree.md ↔ redteam-plan.md linked by node id). Depends on Plan 1's `Graph`/query API being final.
- Plan 3 — Phase reconciliation & bidirectional evidence: draft→refine→reconcile checkpoints (§4); investigate/validate/trace consuming graph queries instead of re-tracing (§5 Investigate & Confirm); disprove-with-receipt wiring into validate (§6); redteam consuming attack-tree + `is_unresolvable` (§7).

**Placeholder scan:** no TBD/TODO/"handle edge cases" steps; every code step carries real code. Task 6 flags a required pre-implementation read of `models.py` (to avoid touching the frozen `Finding`) rather than guessing a field — this is a genuine verification step, not a placeholder.

**Type consistency:** `Node`/`Edge`/`Fact`/`Graph`/`NoPathResult` shapes and the `reaches`/`attacker_controls`/`no_path`/`is_unresolvable`/`merge_tier2`/`build_and_write_tier1` signatures are consistent across all tasks. `NO_PATH_RECEIPT` is the single source of the receipt string.

**One open risk to confirm during Task 6:** the `Finding` model may expose no dataflow-source location field. The task explicitly requires reading `models.py` first and deriving the taint edge from existing fields only (synthetic `external:*` source node) — never adding a field to the frozen contract.
