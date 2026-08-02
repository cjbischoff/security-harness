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
