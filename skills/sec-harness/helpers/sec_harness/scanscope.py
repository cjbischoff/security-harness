"""Canonical scan scope: the one repo_root + scan_scope every phase resolves against.

A single scan targets either a whole repo or a sub-path of a monorepo. Historically each
phase/gate/dedupe/verify resolved paths against whatever base its caller happened to pass,
so a monorepo sub-service scan (target = ``internal/svc``) broke: recon cited repo-root-
relative refs, the architecture agent cited subdir-relative refs, and gates guessed a base
per phase. ``ScanScope`` fixes the base once — ``repo_root`` is the git top-level, ``scan_scope``
is the target relative to it — and persists it to ``kb/scan-scope.json`` (NOT the frozen
``CampaignState``). Everything resolves against ``repo_root``; agents cite repo-root-relative.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanScope:
    """The canonical resolution base for one scan.

    Attributes:
        repo_root: Absolute path to the git top-level (or the target if not a git repo).
        scan_scope: Target path relative to ``repo_root`` ("." for a whole-repo scan).
        path_base: Always ``"repo-root"`` — the declared base all refs resolve against.
        slug: Stable per-scan identity slug (see :func:`sec_harness.repo_memory.repo_slug`).
        sha: Pinned git SHA for the pass (informational).
        doc_roots: Repo-root-relative dirs to search for context docs (scan scope + any
            canonical monorepo service-doc locations for this service).
    """

    repo_root: str
    scan_scope: str
    path_base: str = "repo-root"
    slug: str = ""
    sha: str = ""
    doc_roots: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict of this scope."""
        return {
            "repo_root": self.repo_root, "scan_scope": self.scan_scope,
            "path_base": self.path_base, "slug": self.slug, "sha": self.sha,
            "doc_roots": list(self.doc_roots),
        }

    @classmethod
    def from_dict(cls, d: dict) -> ScanScope:
        """Rebuild a :class:`ScanScope` from :meth:`to_dict` output."""
        return cls(
            repo_root=d["repo_root"], scan_scope=d.get("scan_scope", "."),
            path_base=d.get("path_base", "repo-root"), slug=d.get("slug", ""),
            sha=d.get("sha", ""), doc_roots=list(d.get("doc_roots", [])),
        )


def _git_toplevel(target: Path, runner) -> Path | None:
    """Return the git top-level containing ``target``, or None if not a git repo."""
    try:
        res = runner(["git", "-C", str(target), "rev-parse", "--show-toplevel"],
                     capture_output=True, text=True, check=False)
    except OSError:
        return None
    out = (res.stdout or "").strip()
    if res.returncode == 0 and out:
        return Path(out)
    return None


def _service_doc_roots(repo_root: Path, scan_scope: str) -> list[str]:
    """Canonical monorepo doc dirs for a sub-service, when they exist under ``repo_root``.

    A monorepo often stores a service's docs at the repo root (``docs/services/<svc>``,
    ``docs/global-services/<svc>``) rather than inside the service subdir. Include those so
    discovery does not miss them on a sub-service scan.
    """
    if scan_scope == ".":
        return []
    svc = Path(scan_scope).name
    candidates = [f"docs/services/{svc}", f"docs/global-services/{svc}", f"docs/{svc}"]
    return [c for c in candidates if (repo_root / c).is_dir()]


def resolve(target: str | Path, *, sha: str = "", runner=subprocess.run) -> ScanScope:
    """Resolve the canonical :class:`ScanScope` for a scan target.

    Args:
        target: Path being scanned (repo root or a monorepo sub-path).
        sha: Pinned git SHA for the pass (informational).
        runner: Injectable subprocess runner (for tests).

    Returns:
        A :class:`ScanScope` with ``repo_root`` = git top-level (or the resolved target if
        not a git repo), ``scan_scope`` = target relative to ``repo_root`` ("." if equal),
        and ``doc_roots`` seeded with the scan scope + any canonical service-doc dirs.
    """
    target = Path(target).expanduser().resolve()
    top = _git_toplevel(target, runner)
    repo_root = (top.resolve() if top else target)
    try:
        rel = target.relative_to(repo_root).as_posix()
    except ValueError:
        rel = "."
    scan_scope = rel or "."
    doc_roots = ([] if scan_scope == "." else [scan_scope]) + \
        _service_doc_roots(repo_root, scan_scope)
    return ScanScope(repo_root=str(repo_root), scan_scope=scan_scope, sha=sha,
                     doc_roots=doc_roots)


def write_scope(ws, scope: ScanScope) -> Path:
    """Persist ``scope`` to ``ws.kb/scan-scope.json`` and return the path."""
    ws.kb.mkdir(parents=True, exist_ok=True)
    p = ws.kb / "scan-scope.json"
    p.write_text(json.dumps(scope.to_dict(), indent=2))
    return p


def load_scope(ws) -> ScanScope | None:
    """Load ``ws.kb/scan-scope.json`` or ``None`` if absent."""
    p = ws.kb / "scan-scope.json"
    return ScanScope.from_dict(json.loads(p.read_text())) if p.exists() else None


def rel_to_root(path: str | Path, scope: ScanScope) -> str:
    """Normalize ``path`` to a repo-root-relative POSIX string using ``scope``.

    Accepts an absolute path under ``repo_root``, a path already relative to ``repo_root``,
    or a path relative to ``scan_scope`` (the common agent shorthand). Anything that cannot
    be made repo-root-relative is returned as a POSIX string unchanged.
    """
    root = Path(scope.repo_root)
    p = Path(path)
    if p.is_absolute():
        try:
            return p.relative_to(root).as_posix()
        except ValueError:
            return p.as_posix()
    # already repo-root-relative? (exists or starts with scan_scope)
    if (root / p).exists():
        return p.as_posix()
    if scope.scan_scope != "." and str(p).startswith(scope.scan_scope):
        return p.as_posix()
    # scan-scope-relative?
    if scope.scan_scope != "." and (root / scope.scan_scope / p).exists():
        return (Path(scope.scan_scope) / p).as_posix()
    # default: assume scan-scope-relative when scoped, else as-is
    if scope.scan_scope != ".":
        return (Path(scope.scan_scope) / p).as_posix()
    return p.as_posix()
