"""Test correlation workspace layout and synthetic-member fixture."""

from __future__ import annotations

from pathlib import Path

from sec_harness.correlate.workspace import CorrelationWorkspace
from sec_harness.repo_memory import RepoMemory
from sec_harness.workspace import read_findings
from tests.correlate_fixtures import build_member


def test_correlation_workspace_layout(tmp_path: Path) -> None:
    """Verify CorrelationWorkspace creates the expected directory structure."""
    cw = CorrelationWorkspace(tmp_path / "corr")
    cw.ensure()
    assert cw.edges_path == tmp_path / "corr" / "edges.json"
    assert cw.gates_dir.is_dir()
    assert cw.artifacts_dir.is_dir()


def test_fixture_builds_readable_member(tmp_path: Path) -> None:
    """Verify build_member creates a RepoMemory sidecar readable by ingest."""
    m = build_member(
        tmp_path,
        slug="a-1",
        scan_scope=".",
        findings=[
            {
                "id": "C-1",
                "cls": "deps",
                "status": "confirmed",
                "severity": "low",
                "rule_id": "osv:GHSA-x",
                "file": "package-lock.json",
                "line": 1,
                "message": "vuln",
                "evidence_sources": ["sca:osv:GHSA-x"],
            }
        ],
    )
    # the fixture returns a manifest-member dict pointing at the sidecar
    assert m["slug"] == "a-1" and m["scan_scope"] == "."
    # Reconstruct the sidecar path directly (same as fixture pinned it)
    repo_root = Path(m["repo_root"])
    sidecar_root = repo_root / ".sec-harness" / m["slug"]
    rm = RepoMemory(root=sidecar_root)
    assert any(f.id == "C-1" for f in read_findings(rm.workspace))
