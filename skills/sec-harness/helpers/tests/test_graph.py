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
    node = restored.node("a.py:1:f")
    assert node is not None
    assert node.name == "f"
    assert restored.node("missing") is None


def test_save_and_load_graph(tmp_path):
    ws = _ws(tmp_path)
    graph = g.Graph(1, "sha1", ["tier-1"], [], [], [], [])
    path = g.save_graph(ws, graph)
    assert path == ws.kb / "graph.json"
    assert g.load_graph(ws) == graph


FIXTURE = Path(__file__).parent / "fixtures" / "graph_target"


def test_build_tier1_emits_nodes_and_call_edge():
    graph = g.build_tier1(FIXTURE, sha="deadbeef")
    assert graph.version == 1
    assert graph.tiers == ["tier-1"]
    ids = {n.id for n in graph.nodes}
    assert "app/api.py:4:handler" in ids
    assert "app/db.py:1:run_query" in ids
    handler_node = graph.node("app/api.py:4:handler")
    assert handler_node is not None
    assert handler_node.attrs["lang"] == "py"
    # handler() calls run_query() -> a call edge exists between the two nodes
    assert any(
        e.kind == "calls"
        and e.src == "app/api.py:4:handler"
        and e.dst == "app/db.py:1:run_query"
        for e in graph.edges
    )
