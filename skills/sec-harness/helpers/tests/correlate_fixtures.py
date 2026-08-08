"""Build synthetic member sidecars for correlation tests (no real repos needed)."""

from __future__ import annotations

from pathlib import Path

from sec_harness.models import Finding
from sec_harness.repo_memory import RepoMemory
from sec_harness.workspace import write_findings


def build_member(
    base: Path, *, slug: str, scan_scope: str, findings: list[dict]
) -> dict:
    """Create a member sidecar under ``base`` and return its manifest-member dict.

    The sidecar is a real :class:`RepoMemory` workspace so ingest reads it exactly as it would a
    production one. ``slug`` is used as the repo-root directory name for test isolation.

    Args:
        base: tmp dir to build under.
        slug: member slug (also the repo-root dir name).
        scan_scope: "." or a subpath.
        findings: list of Finding dicts (``Finding.from_dict`` shape).

    Returns:
        A manifest-member dict ``{slug, repo_root, scan_scope, role}`` (role defaults rbac-source;
        override in the returned dict as needed).
    """
    repo_root = base / slug
    target = repo_root if scan_scope == "." else repo_root / scan_scope
    target.mkdir(parents=True, exist_ok=True)
    rm = RepoMemory(root=repo_root / ".sec-harness" / slug)
    rm.workspace.ensure()
    write_findings(rm.workspace, [Finding.from_dict(f) for f in findings])
    return {
        "slug": slug,
        "repo_root": str(repo_root),
        "scan_scope": scan_scope,
        "role": "rbac-source",
    }
