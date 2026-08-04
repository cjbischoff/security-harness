"""Tests for Workspace path overrides."""

import json
from pathlib import Path

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import (
    Workspace,
    load_paths,
    read_agent_return,
    read_findings,
    record_agent_return,
    write_findings,
)


def test_defaults_unchanged(tmp_path):
    """Default behavior unchanged when no overrides provided."""
    ws = Workspace(tmp_path)
    assert ws.kb == tmp_path / "kb"
    assert ws.findings_dir == tmp_path / "findings"
    assert ws.sarif_path == tmp_path / "report.sarif"
    assert ws.report_path == tmp_path / "report.md"


def test_accepts_string_root(tmp_path):
    """A str root is coerced to Path so agent-authored commands don't crash.

    The agent prompts embed ``Workspace('<path>')`` with a bare string; without
    coercion the first path property raises ``TypeError`` (str / str).
    """
    ws = Workspace(str(tmp_path))
    assert ws.kb == tmp_path / "kb"
    assert isinstance(ws.root, Path)


def test_coerces_string_overrides(tmp_path):
    """String override paths are coerced too."""
    ws = Workspace(str(tmp_path), findings_dir_override=str(tmp_path / "f"))
    assert ws.findings_dir == tmp_path / "f"
    assert isinstance(ws.findings_dir, Path)


def test_overrides(tmp_path):
    """Path overrides are honored."""
    ws = Workspace(
        tmp_path,
        reports_dir=tmp_path / "R",
        findings_dir_override=tmp_path / "F",
        kb_dir_override=tmp_path / "K",
    )
    assert ws.kb == tmp_path / "K"
    assert ws.findings_dir == tmp_path / "F"
    assert ws.sarif_path == tmp_path / "R" / "report.sarif"
    assert ws.report_path == tmp_path / "R" / "report.md"
    assert ws.findings_json_path == tmp_path / "R" / "findings.json"


def test_ensure_creates_all_trees(tmp_path):
    """ensure() creates all overridden directories."""
    ws = Workspace(
        tmp_path,
        reports_dir=tmp_path / "R",
        findings_dir_override=tmp_path / "F",
        kb_dir_override=tmp_path / "K",
    )
    ws.ensure()
    assert (tmp_path / "K").is_dir()
    assert (tmp_path / "F").is_dir()
    assert (tmp_path / "R").is_dir()


def test_load_paths_flag_over_config(tmp_path):
    """Flag args override paths.json values."""
    cfg = tmp_path / "paths.json"
    cfg.write_text(
        json.dumps(
            {
                "reports_dir": str(tmp_path / "cfgR"),
                "kb_dir": str(tmp_path / "cfgK"),
            }
        )
    )
    ws = load_paths(
        workspace=tmp_path / "w",
        paths_config=cfg,
        reports_dir=tmp_path / "flagR",
    )
    assert ws.reports_dir == tmp_path / "flagR"  # flag wins
    assert ws.kb_dir_override == tmp_path / "cfgK"  # config used where no flag
    assert ws.findings_dir_override is None  # derive


def test_load_paths_derive_when_empty(tmp_path):
    """With minimal args, paths are None (derive at use-time)."""
    ws = load_paths(workspace=tmp_path / "w")
    assert ws.root == tmp_path / "w"
    assert ws.reports_dir is None and ws.kb_dir_override is None


def test_load_paths_requires_workspace(tmp_path):
    """No workspace flag and none in config -> ValueError."""
    import json

    import pytest
    cfg = tmp_path / "paths.json"
    cfg.write_text(json.dumps({"reports_dir": str(tmp_path / "R")}))
    with pytest.raises(ValueError):
        load_paths(workspace=None, paths_config=cfg)


def _finding(fid: str) -> Finding:
    """Minimal finding fixture."""
    return Finding(
        id=fid,
        rule_id="r",
        cls="sqli",
        status=FindingStatus.RAW,
        severity=Severity.MEDIUM,
        file="a.py",
        line=1,
        message="m",
    )


def test_write_findings_atomic_no_temp_left(tmp_path):
    """write_findings leaves the final file and no stray temp artifacts (T8)."""
    ws = Workspace(tmp_path)
    write_findings(ws, [_finding("F-1")])
    names = [p.name for p in ws.findings_dir.iterdir()]
    assert names == ["F-1.json"]  # exactly the final file — no *.tmp sidecar
    assert read_findings(ws)[0].id == "F-1"


def test_write_findings_no_partial_on_serialize_failure(tmp_path, monkeypatch):
    """A serialization crash mid-write must not truncate an existing file (T8)."""
    import sec_harness.workspace as wsmod

    ws = Workspace(tmp_path)
    write_findings(ws, [_finding("F-1")])
    target = ws.findings_dir / "F-1.json"
    good = target.read_text()

    boom = _finding("F-1")
    monkeypatch.setattr(
        wsmod.json, "dumps", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom"))
    )
    try:
        write_findings(ws, [boom])
    except ValueError:
        pass
    # original content intact; no half-written temp file abandoned in the dir
    assert target.read_text() == good
    assert [p.name for p in ws.findings_dir.iterdir()] == ["F-1.json"]


def test_agent_return_roundtrips(tmp_path):
    """Agent final returns persist to runs/<agent>.txt and read back (T13)."""
    ws = Workspace(tmp_path)
    record_agent_return(ws, "investigate-sqli", "found 2 candidates")
    assert (ws.runs / "investigate-sqli.txt").is_file()
    assert read_agent_return(ws, "investigate-sqli") == "found 2 candidates"
    assert read_agent_return(ws, "missing") is None


def test_ensure_creates_runs(tmp_path):
    """ensure() creates the runs directory (T13)."""
    ws = Workspace(tmp_path)
    ws.ensure()
    assert ws.runs.is_dir()


def test_read_findings_skips_malformed_without_crashing(tmp_path, capsys):
    """One malformed finding must not crash the pipeline (dogfood ISSUE-015).

    read_findings returns the parseable findings and warns (to stderr) about the
    skipped file, rather than raising and halting every downstream phase.
    """
    ws = Workspace(tmp_path)
    write_findings(ws, [_finding("F-1")])
    # a finding with an out-of-enum severity (exactly what an agent emitted)
    (ws.findings_dir / "BAD.json").write_text(
        json.dumps({"id": "BAD", "rule_id": "r", "cls": "sqli", "status": "raw",
                    "severity": "informational", "file": "a.py", "line": 1, "message": "m"})
    )
    findings = read_findings(ws)  # must NOT raise
    assert [f.id for f in findings] == ["F-1"]
    err = capsys.readouterr().err
    assert "BAD.json" in err
