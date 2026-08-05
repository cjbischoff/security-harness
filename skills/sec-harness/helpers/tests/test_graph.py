from pathlib import Path

from sec_harness import graph as g
from sec_harness.models import Finding, FindingStatus, Severity
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


def _candidate(file: str = "b.py", line: int = 1,
                evidence_sources: list[str] | None = None) -> Finding:
    return Finding(
        id="F-1", rule_id="r", cls="sqli", status=FindingStatus.CANDIDATE,
        severity=Severity.HIGH, file=file, line=line, message="t",
        evidence_sources=evidence_sources or ["codeql:dataflow"],
    )


def test_merge_tier2_adds_taint_edge_and_bumps_version():
    graph = g.build_tier1(FIXTURE, sha="x")
    cand = _candidate(file="app/db.py", line=1)
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


def test_taint_id_helpers_match_merge_tier2():
    graph = g.build_tier1(FIXTURE, sha="x")
    cand = _candidate(file="app/db.py", line=1)
    g.merge_tier2(graph, [cand], taint_langs=["py"])
    taint_edges = [e for e in graph.edges if e.kind == "taint"]
    assert len(taint_edges) == 1
    assert taint_edges[0].src == g.taint_source_id(cand)
    assert taint_edges[0].dst == g.taint_sink_id(cand)


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


def test_call_edges_respect_word_boundary_and_substrings(tmp_path):
    """Call-edge detection must match whole call tokens, not substrings.

    Locks the semantics the optimized detector must preserve: a body that calls
    ``foobar()`` creates an edge to ``foobar`` but NOT to the substring name
    ``bar``; a body that calls both creates both edges.
    """
    src = tmp_path / "mod.py"
    src.write_text(
        "def bar():\n"
        "    return 1\n"
        "def foobar():\n"
        "    return 2\n"
        "def only_foobar():\n"
        "    return foobar()\n"
        "def both():\n"
        "    return bar() + foobar()\n"
    )
    graph = g.build_tier1(tmp_path, sha="x")
    calls = {(e.src.split(":")[-1], e.dst.split(":")[-1]) for e in graph.edges if e.kind == "calls"}
    assert ("only_foobar", "foobar") in calls
    assert ("only_foobar", "bar") not in calls  # substring must not match
    assert ("both", "bar") in calls
    assert ("both", "foobar") in calls


def test_build_tier1_flags_entry_points():
    graph = g.build_tier1(FIXTURE, sha="deadbeef")
    widget_node = graph.node("app/api.py:10:get_widget")
    assert widget_node is not None
    assert widget_node.attrs["is_entry_point"] is True
    assert "route" in widget_node.attrs["entry_point_reason"]


def test_build_tier1_does_not_flag_internal_helper():
    graph = g.build_tier1(FIXTURE, sha="deadbeef")
    db_node = graph.node("app/db.py:1:run_query")
    assert db_node is not None
    assert db_node.attrs["is_entry_point"] is False
    assert "entry_point_reason" not in db_node.attrs


def test_entry_point_nodes_returns_only_flagged_nodes():
    graph = g.build_tier1(FIXTURE, sha="deadbeef")
    flagged = g.entry_point_nodes(graph)
    assert all(n.attrs.get("is_entry_point") for n in flagged)
    assert any(n.id == "app/api.py:10:get_widget" for n in flagged)


def test_symbol_at_returns_enclosing_symbol():
    graph = g.build_tier1(FIXTURE, sha="x")
    # handler is defined at app/api.py:4; a line at/after 4 resolves to it
    assert g.symbol_at(graph, "app/api.py", 6) == "handler"
    assert g.symbol_at(graph, "app/api.py", 4) == "handler"
    # a line before any definition in the file resolves to nothing
    assert g.symbol_at(graph, "app/api.py", 1) is None
    # unknown file resolves to nothing
    assert g.symbol_at(graph, "nope.py", 10) is None
