"""End-to-end deterministic pipeline test against the vulnerable fixture."""

import json
import shutil
from pathlib import Path

import pytest

from sec_harness.cli import run_scan
from sec_harness.workspace import Workspace

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def test_scan_fixture_finds_both_seeded_vulns(tmp_path, fixture_repo):
    ws_root = tmp_path / "workspace"
    rules = fixture_repo.parent.parent / "rules" / "smoke.yaml"
    findings = run_scan(str(fixture_repo), Workspace(Path(ws_root)), str(rules), sha="testsha")
    classes = {f.cls for f in findings}
    assert "sqli" in classes
    assert "secrets" in classes

    ws = Workspace(ws_root)
    assert ws.sarif_path.exists()
    assert ws.report_path.exists()
    sarif = json.loads(ws.sarif_path.read_text())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= 2
    # findings persisted with stable ids
    assert (ws.findings_dir / "F-0001.json").exists()


def test_run_scan_records_prefilter_stage(tmp_path, fixture_repo):
    import shutil

    import pytest

    if shutil.which("semgrep") is None:
        pytest.skip("semgrep not installed")

    from sec_harness.cli import run_scan
    from sec_harness.state import load_state
    from sec_harness.workspace import Workspace

    ws_root = tmp_path / "workspace"
    rules = fixture_repo.parent.parent / "rules" / "smoke.yaml"
    run_scan(str(fixture_repo), Workspace(Path(ws_root)), str(rules), sha="s1")
    assert load_state(Workspace(ws_root)).stages.get("prefilter") == "done"


def test_run_scan_does_not_advance_pass(tmp_path, fixture_repo):
    import shutil

    import pytest

    if shutil.which("semgrep") is None:
        pytest.skip("semgrep not installed")

    from sec_harness.cli import run_scan
    from sec_harness.state import begin_pass, load_state
    from sec_harness.workspace import Workspace

    ws_root = tmp_path / "workspace"
    ws = Workspace(ws_root)
    ws.ensure()
    begin_pass(ws, "s1")  # supervisor owns pass lifecycle -> pass 1
    rules = fixture_repo.parent.parent / "rules" / "smoke.yaml"
    run_scan(str(fixture_repo), Workspace(Path(ws_root)), str(rules), sha="s1")
    # prefilter must NOT spuriously increment the pass counter
    assert load_state(ws).pass_number == 1
