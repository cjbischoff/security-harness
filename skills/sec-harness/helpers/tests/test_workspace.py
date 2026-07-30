"""Tests for Workspace path overrides."""

import json

from sec_harness.workspace import Workspace, load_paths


def test_defaults_unchanged(tmp_path):
    """Default behavior unchanged when no overrides provided."""
    ws = Workspace(tmp_path)
    assert ws.kb == tmp_path / "kb"
    assert ws.findings_dir == tmp_path / "findings"
    assert ws.sarif_path == tmp_path / "report.sarif"
    assert ws.report_path == tmp_path / "report.md"


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
