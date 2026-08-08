"""Tests for per-repo persistent scan memory."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from sec_harness.campaign import record_stage
from sec_harness.repo_memory import PHASES, RepoMemory, memory_root, repo_slug
from sec_harness.state import begin_pass


def test_memory_root_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SEC_HARNESS_HOME", str(tmp_path / "mem"))
    assert memory_root() == tmp_path / "mem"
    # env override wins even when a target is given
    assert memory_root(tmp_path / "repo") == tmp_path / "mem"
    monkeypatch.delenv("SEC_HARNESS_HOME")
    assert memory_root().name == ".sec-harness"


def test_memory_root_defaults_in_repo(monkeypatch, tmp_path):
    monkeypatch.delenv("SEC_HARNESS_HOME", raising=False)
    # default (no env) with a target → in-repo <target>/.sec-harness sidecar
    assert memory_root(tmp_path) == tmp_path.resolve() / ".sec-harness"
    # for_target roots the campaign at <target>/.sec-harness/<slug>/
    m = RepoMemory.for_target(tmp_path, runner=lambda *a, **k: type(
        "R", (), {"returncode": 128, "stdout": "", "stderr": ""})())
    assert m.root.parent == tmp_path.resolve() / ".sec-harness"
    assert m.root.name.startswith(tmp_path.name.lower())


def test_ensure_seeds_self_ignoring_gitignore(tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    m = RepoMemory.for_target(repo, runner=lambda *a, **k: type(
        "R", (), {"returncode": 128, "stdout": "", "stderr": ""})())
    m.ensure(target=str(repo))
    ignore = repo / ".sec-harness" / ".gitignore"
    assert ignore.exists() and ignore.read_text().strip().endswith("*")
    # idempotent: an existing .gitignore is never clobbered
    ignore.write_text("custom\n")
    m.ensure(target=str(repo))
    assert ignore.read_text() == "custom\n"


def test_repo_slug_prefers_remote_and_is_stable(tmp_path):
    class R:
        returncode = 0; stdout = "https://github.com/acme/widgets.git\n"; stderr = ""
    s1 = repo_slug(tmp_path, runner=lambda *a, **k: R())
    s2 = repo_slug(tmp_path, runner=lambda *a, **k: R())
    assert s1 == s2                      # stable
    assert s1.startswith("widgets-")     # from remote basename
    # falls back to path basename when no remote
    class NoRemote:
        returncode = 128; stdout = ""; stderr = "no remote"
    s3 = repo_slug(tmp_path / "myproj", runner=lambda *a, **k: NoRemote())
    assert s3.startswith("myproj-")


def test_for_target_and_ensure_seeds_index(tmp_path):
    m = RepoMemory.for_target("/x/repo", base=tmp_path, runner=lambda *a, **k: type("R", (), {"returncode":128,"stdout":"","stderr":""})())
    m.ensure(target="/x/repo")
    assert m.index_path.exists()
    assert (m.root / "kb").is_dir() and (m.root / "findings").is_dir()
    assert "sec-harness memory" in m.index_path.read_text()


def test_run_status_resume_and_finished(tmp_path):
    m = RepoMemory(root=tmp_path / "slug"); m.ensure()
    ws = m.workspace
    # no state yet
    st = m.run_status(); assert st["finished"] is False and st["next_phase"] == PHASES[0]
    begin_pass(ws, "sha1")
    for stage in ["recon", "architecture", "threat_model"]:
        record_stage(ws, stage)
    st = m.run_status()
    assert st["finished"] is False and st["resumable"] is True
    assert st["next_phase"] == "prefilter"     # first not-yet-done in canonical order
    for stage in [p for p in PHASES if p not in ("recon", "architecture", "threat_model")]:
        record_stage(ws, stage)
    st = m.run_status()
    assert st["finished"] is True and st["resumable"] is False and st["next_phase"] is None


def test_record_learning_appends_and_indexes(tmp_path):
    m = RepoMemory(root=tmp_path / "slug"); m.ensure()
    p = m.record_learning("mcrypt token forgery confirmed in Crypter.php", today=date(2026, 7, 30), tag="crypto")
    assert p.exists() and "mcrypt token forgery" in p.read_text()
    # second learning same day appends to same file
    m.record_learning("SAST clean elsewhere", today=date(2026, 7, 30))
    assert p.read_text().count("- ") == 2
    idx = m.index_path.read_text()
    assert "2026-07-30 [crypto]" in idx and "mcrypt token forgery" in idx


def test_update_status_rewrites_block(tmp_path):
    m = RepoMemory(root=tmp_path / "slug"); m.ensure()
    begin_pass(m.workspace, "shaX"); record_stage(m.workspace, "recon")
    m.update_status()
    txt = m.index_path.read_text()
    assert "IN PROGRESS" in txt and "shaX" in txt and "## Learnings log" in txt


def _origin(url: str, toplevel: str | None = None):
    def runner(cmd, *, capture_output=True, text=True, check=False):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        if "remote" in cmd and "get-url" in cmd:
            R.stdout = url + "\n"
        elif "rev-parse" in cmd and "--show-toplevel" in cmd:
            R.stdout = (toplevel or "") + "\n"
        return R()
    return runner


def test_monorepo_subdirs_get_distinct_slugs(tmp_path: Path):
    repo = tmp_path / "mono"
    (repo / "internal" / "svcA").mkdir(parents=True)
    (repo / "internal" / "svcB").mkdir(parents=True)
    url = "git@github.com:org/mono.git"
    a = repo_slug(repo / "internal" / "svcA", runner=_origin(url, str(repo)))
    b = repo_slug(repo / "internal" / "svcB", runner=_origin(url, str(repo)))
    assert a != b, "monorepo sub-services must not collide"


def test_whole_repo_slug_stable(tmp_path: Path):
    repo = tmp_path / "solo"
    repo.mkdir()
    url = "git@github.com:org/solo.git"
    s1 = repo_slug(repo, runner=_origin(url, str(repo)))
    s2 = repo_slug(repo, runner=_origin(url, str(repo)))
    assert s1 == s2
    assert s1.startswith("solo-")
