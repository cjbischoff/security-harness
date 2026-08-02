"""Tests for the scan CLI's run_scan wiring."""

import json

from sec_harness.cli import run_scan
from sec_harness.workspace import Workspace


def test_run_scan_writes_findings_json_to_reports_dir(tmp_path, monkeypatch):
    from sec_harness import cli

    monkeypatch.setattr(cli, "run_semgrep", lambda *a, **k: [])
    ws = Workspace(tmp_path / "w", reports_dir=tmp_path / "R")
    run_scan("t", ws, "cfg", sha="deadbeef")
    assert (tmp_path / "R" / "report.sarif").exists()
    assert (tmp_path / "R" / "report.md").exists()
    fj = tmp_path / "R" / "findings.json"
    assert fj.exists() and json.loads(fj.read_text()) == []


def test_scan_defaults_to_repo_memory(tmp_path, monkeypatch):
    from sec_harness import cli
    monkeypatch.setenv("SEC_HARNESS_HOME", str(tmp_path / "mem"))
    target = tmp_path / "repo"; (target / "a.py").parent.mkdir(parents=True, exist_ok=True)
    (target / "a.py").write_text("x=1\n")
    monkeypatch.setattr(cli, "run_semgrep", lambda *a, **k: [])
    rc = cli.main(["scan", "--target", str(target), "--config", "rules/smoke.yaml"])
    assert rc == 0
    # memory folder created under SEC_HARNESS_HOME with a seeded MEMORY.md + state
    # (the home also holds a .gitignore sidecar; select the repo-slug dir explicitly)
    slugs = [p for p in (tmp_path / "mem").iterdir() if p.is_dir()]
    assert slugs and (slugs[0] / "MEMORY.md").exists()
    assert (slugs[0] / "findings").is_dir()


def test_memory_command_status_and_learn(tmp_path, monkeypatch, capsys):
    from sec_harness import cli
    monkeypatch.setenv("SEC_HARNESS_HOME", str(tmp_path / "mem"))
    target = tmp_path / "repo"; target.mkdir()
    assert cli.main(["memory", "--target", str(target)]) == 0
    assert "status:" in capsys.readouterr().out
    assert cli.main(["memory", "--target", str(target), "--learn", "found X", "--tag", "note"]) == 0
    slug = next(p for p in (tmp_path / "mem").iterdir() if p.is_dir())
    assert "found X" in (slug / "MEMORY.md").read_text()
