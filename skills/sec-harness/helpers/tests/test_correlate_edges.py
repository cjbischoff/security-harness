"""Tests for shared-dependency edge roll-up."""

from __future__ import annotations

from pathlib import Path

from sec_harness.correlate.edges import shared_dependency_edges
from sec_harness.correlate.ingest import ingest
from sec_harness.correlate.manifest import Manifest, Member
from tests.correlate_fixtures import build_member


def _dep(fid, osv, sev="low"):
    return {"id": fid, "cls": "deps", "status": "confirmed", "severity": sev,
            "rule_id": f"osv:{osv}", "file": "lock", "line": 1, "message": "m",
            "evidence_sources": [f"sca:osv:{osv}"]}


def test_shared_dependency_rolls_up_across_members(tmp_path: Path):
    ma = build_member(tmp_path, slug="a-1", scan_scope=".", findings=[_dep("C-1", "GHSA-shared")])
    mb = build_member(tmp_path, slug="b-1", scan_scope=".", findings=[_dep("C-9", "GHSA-shared"),
                                                                       _dep("C-8", "GHSA-solo")])
    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    edges = shared_dependency_edges(ingest(man))
    shared = [e for e in edges if e.key == "GHSA-shared"]
    assert len(shared) == 1
    assert set(shared[0].members) == {"a-1#.", "b-1#."}
    # GHSA-solo appears in only one member -> not a shared edge
    assert not any(e.key == "GHSA-solo" for e in edges)


def test_same_class_recurrence_flags_systemic(tmp_path: Path):
    from sec_harness.correlate.edges import same_class_recurrence_edges

    def _authz(fid, fp):
        return {"id": fid, "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
                "rule_id": "ce-from-payload", "file": "x.go", "line": 1, "message": "m",
                "evidence_sources": ["ast-grep:x"], "fingerprint": fp}

    ma = build_member(tmp_path, slug="a-1", scan_scope=".", findings=[_authz("N-1", "authz|ce|src")])
    mb = build_member(tmp_path, slug="b-1", scan_scope=".", findings=[_authz("N-2", "authz|ce|src")])
    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    edges = same_class_recurrence_edges(ingest(man))
    assert len(edges) == 1
    assert edges[0].detail["systemic"] is True
    assert edges[0].detail["cls"] == "authz"
    assert set(edges[0].members) == {"a-1#.", "b-1#."}


def test_control_enforces_joins_privilege_across_roles(tmp_path):
    from sec_harness.correlate.edges import control_enforces_edges
    from sec_harness.correlate.ingest import ingest
    from sec_harness.correlate.manifest import Manifest, Member
    from tests.correlate_fixtures import build_member

    # rbac-source finding names a privilege; service-enforcer finding names the same privilege
    ma = build_member(tmp_path, slug="rbac-1", scan_scope=".", findings=[
        {"id": "A-1", "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
         "rule_id": "context:claimed-control", "file": "src/rbac/spec.js", "line": 1,
         "message": "privilege 'aem analytics findings write' unscoped; enforcement out-of-repo",
         "evidence_sources": ["ast-grep:x"]}])
    mb = {**build_member(tmp_path, slug="svc-1", scan_scope=".", findings=[
        {"id": "E-1", "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
         "rule_id": "no-mr-check", "file": "api.go", "line": 9,
         "message": "handler for 'aem analytics findings write' has no MR check",
         "evidence_sources": ["ast-grep:y"]}]), "role": "service-enforcer"}
    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    edges = control_enforces_edges(ingest(man))
    ce = [e for e in edges if e.type == "control-enforces"]
    assert any(e.key == "aem analytics findings write" for e in ce)
    e = next(e for e in ce if e.key == "aem analytics findings write")
    assert set(e.members) == {"rbac-1#.", "svc-1#."}
    assert e.detail["from"].startswith("rbac-1#.") and e.detail["to"].startswith("svc-1#.")
