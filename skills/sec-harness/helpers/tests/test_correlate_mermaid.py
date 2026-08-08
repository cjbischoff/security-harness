from sec_harness.correlate.manifest import Manifest, Member
from sec_harness.correlate.edges import Edge
from sec_harness.correlate.mermaid import component_graph, _node_id


def _manifest():
    return Manifest(product="p", members=[
        Member(slug="rbac", repo_root="/r", scan_scope=".", role="rbac-source"),
        Member(slug="svc", repo_root="/s", scan_scope="internal/x", role="service-enforcer"),
    ])


def test_node_id_is_mermaid_safe():
    assert _node_id("go-1a2b#internal/x") == "go_1a2b_internal_x"


def test_component_graph_is_deterministic_and_draws_control_enforces():
    m = _manifest()
    edges = [Edge(type="control-enforces", members=["svc#internal/x", "rbac#."],
                  key="read data", detail={"join": "deterministic"})]
    out = component_graph(m, edges)
    assert out == component_graph(m, edges)          # deterministic
    assert out.startswith("flowchart LR")
    assert "subgraph rbac-source" in out and "subgraph service-enforcer" in out
    assert "-->|read data|" in out                    # privilege-labeled enforcement edge
    assert "same-class" not in out


def test_component_graph_draws_shared_dependency_dashed():
    m = _manifest()
    edges = [Edge(type="shared-dependency", members=["svc#internal/x", "rbac#."],
                  key="GHSA-1", detail={"reachability": {}})]
    out = component_graph(m, edges)
    assert "-.->|GHSA-1|" in out
