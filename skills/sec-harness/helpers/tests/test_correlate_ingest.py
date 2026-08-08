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


def test_ingest_tags_cross_repo_ids_readonly(tmp_path: Path) -> None:
    """Verify ingest reads-only, tagging findings with cross_repo_ids (member_key#file:line:rule_id)."""
    import hashlib

    from sec_harness.correlate.ingest import ingest
    from sec_harness.correlate.manifest import Manifest, Member

    ma = build_member(
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
                "message": "m",
                "evidence_sources": ["sca:osv:GHSA-x"],
            }
        ],
    )
    mb = build_member(
        tmp_path,
        slug="go-1",
        scan_scope="internal/svc",
        findings=[
            {
                "id": "N-1",
                "cls": "authz",
                "status": "needs-deployment-testing",
                "severity": "medium",
                "rule_id": "r",
                "file": "api.go",
                "line": 9,
                "message": "m",
                "evidence_sources": ["ast-grep:x"],
            }
        ],
    )
    man = Manifest(
        product="p",
        members=[
            Member(**ma),
            Member(**{**mb, "role": "service-enforcer"}),
        ],
    )

    # snapshot member sidecars to assert immutability
    def _snap(root: Path) -> dict:
        return {
            p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*"))
            if p.is_file()
        }

    before = {
        ma["slug"]: _snap(Path(ma["repo_root"])),
        mb["slug"]: _snap(Path(mb["repo_root"])),
    }

    ings = ingest(man)
    ids = {i.cross_repo_id for i in ings}
    assert "a-1#.:package-lock.json:1:osv:GHSA-x" in ids
    assert "go-1#internal/svc:api.go:9:r" in ids
    assert {i.role for i in ings} == {"rbac-source", "service-enforcer"}

    after = {
        ma["slug"]: _snap(Path(ma["repo_root"])),
        mb["slug"]: _snap(Path(mb["repo_root"])),
    }
    assert before == after, "ingest must not modify any member sidecar"
