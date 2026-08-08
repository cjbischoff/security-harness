from __future__ import annotations

from pathlib import Path

from sec_harness.cli import write_scan_scope  # new thin helper added in Step 4
from sec_harness.scanscope import load_scope
from sec_harness.workspace import Workspace


def _fake_git(top: str, origin: str):
    def runner(cmd, capture_output=True, text=True, check=False):
        class R:
            returncode = 0
            stderr = ""
            stdout = (top if "show-toplevel" in cmd else origin) + "\n"
        return R()
    return runner


def test_write_scan_scope_persists(tmp_path: Path):
    repo = tmp_path / "mono"
    (repo / "internal" / "svc").mkdir(parents=True)
    ws = Workspace(tmp_path / "ws")
    ws.ensure()
    write_scan_scope(ws, repo / "internal" / "svc", sha="cafe",
                     runner=_fake_git(str(repo), "git@github.com:org/mono.git"))
    scope = load_scope(ws)
    assert scope is not None
    assert scope.scan_scope == "internal/svc"
    assert scope.sha == "cafe"
    assert scope.slug.startswith("svc-")
