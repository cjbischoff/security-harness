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
