from __future__ import annotations

from pathlib import Path

from sec_harness.scanscope import ScanScope, load_scope, rel_to_root, resolve, write_scope
from sec_harness.workspace import Workspace


def _fake_git(toplevel: str):
    def runner(cmd, capture_output=True, text=True, check=False):
        class R:
            returncode = 0
            stdout = toplevel + "\n"
            stderr = ""
        return R()
    return runner


def test_resolve_monorepo_subdir(tmp_path: Path):
    repo = tmp_path / "monorepo"
    (repo / "internal" / "svc").mkdir(parents=True)
    scope = resolve(repo / "internal" / "svc", sha="abc123",
                    runner=_fake_git(str(repo)))
    assert scope.repo_root == str(repo)
    assert scope.scan_scope == "internal/svc"
    assert scope.path_base == "repo-root"
    assert scope.sha == "abc123"


def test_resolve_whole_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    scope = resolve(repo, runner=_fake_git(str(repo)))
    assert scope.scan_scope == "."


def test_resolve_non_git_falls_back_to_target(tmp_path: Path):
    d = tmp_path / "plain"
    d.mkdir()

    def failing(cmd, capture_output=True, text=True, check=False):
        class R:
            returncode = 128
            stdout = ""
            stderr = "not a git repo"
        return R()

    scope = resolve(d, runner=failing)
    assert scope.repo_root == str(d.resolve())
    assert scope.scan_scope == "."


def test_write_and_load_roundtrip(tmp_path: Path):
    ws = Workspace(tmp_path / "ws")
    ws.ensure()
    scope = ScanScope(repo_root=str(tmp_path), scan_scope="internal/svc",
                      slug="repo-1a2b3c4d", sha="deadbeef",
                      doc_roots=["internal/svc", "docs/services/svc"])
    p = write_scope(ws, scope)
    assert p == ws.kb / "scan-scope.json"
    loaded = load_scope(ws)
    assert loaded == scope


def test_load_missing_returns_none(tmp_path: Path):
    ws = Workspace(tmp_path / "ws")
    ws.ensure()
    assert load_scope(ws) is None


def test_rel_to_root_absolute_and_subdir(tmp_path: Path):
    scope = ScanScope(repo_root=str(tmp_path), scan_scope="internal/svc")
    # absolute path under repo_root -> repo-root-relative
    assert rel_to_root(tmp_path / "internal/svc/a.go", scope) == "internal/svc/a.go"
    # scan-scope-relative path -> repo-root-relative
    assert rel_to_root("a.go", scope) == "internal/svc/a.go"
    # already repo-root-relative -> unchanged
    assert rel_to_root("internal/svc/a.go", scope) == "internal/svc/a.go"
