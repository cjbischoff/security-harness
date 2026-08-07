"""Tests for patch application + static patch verification."""

import shutil
from pathlib import Path

import pytest

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.verify import apply_patch, verify_findings, verify_patch
from sec_harness.workspace import Workspace, read_findings, write_findings

HELPERS = Path(__file__).parent.parent
FIXTURE = HELPERS / "fixtures" / "vulnerable_repo"
CONFIG = str(HELPERS / "rules" / "smoke.yaml")
GOLDEN = (HELPERS / "fixtures" / "golden_sqli_patch.diff").read_text()

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def test_apply_patch_modifies_copy(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    assert apply_patch(repo, GOLDEN) is True
    text = (repo / "app.py").read_text()
    assert "id = ?" in text            # parameterized form present
    assert "'%s'\" % uid" not in text  # vulnerable form gone


def test_apply_patch_returns_false_on_bad_diff(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    assert apply_patch(repo, "--- a/nope.py\n+++ b/nope.py\n@@ -1,1 +1,1 @@\n-x\n+y\n") is False


@needs_semgrep
def test_verify_patch_confirms_sqli_fixed():
    # golden patch removes the sqli hit in app.py -> verified-static
    assert verify_patch(str(FIXTURE), GOLDEN, CONFIG, "app.py", "sqli") == "verified-static"


@needs_semgrep
def test_verify_patch_reports_not_fixed_for_untouched_class():
    # golden patch fixes sqli but leaves the hardcoded secret -> secrets still fires
    assert verify_patch(str(FIXTURE), GOLDEN, CONFIG, "app.py", "secrets") == "not-fixed"


@needs_semgrep
def test_verify_patch_static_only_when_class_not_detectable():
    # no ssrf rule fires in the fixture -> cannot auto-verify
    assert verify_patch(str(FIXTURE), GOLDEN, CONFIG, "app.py", "ssrf") == "static-only"


def _confirmed(id_, cls, patch="--- a/x\n+++ b/x\n"):
    return Finding(id=id_, rule_id="r", cls=cls, status=FindingStatus.CONFIRMED,
                   severity=Severity.HIGH, file="app.py", line=1, message="m",
                   patch_diff=patch)


def test_verify_findings_promotes_verified_to_fixed(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_confirmed("F-0002", "sqli")])
    n = verify_findings(ws, "t", "c", verifier=lambda *a, **k: "verified-static")
    assert n == 1
    f = read_findings(ws)[0]
    assert f.status is FindingStatus.FIXED
    assert f.verification == "verified-static"


def test_verify_findings_static_only_stays_confirmed(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_confirmed("F-0001", "secrets")])
    n = verify_findings(ws, "t", "c", verifier=lambda *a, **k: "static-only")
    assert n == 0
    f = read_findings(ws)[0]
    assert f.status is FindingStatus.CONFIRMED
    assert f.verification == "static-only"


def test_verify_findings_skips_findings_without_patch(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_confirmed("F-0003", "sqli", patch="")])
    n = verify_findings(ws, "t", "c", verifier=lambda *a, **k: "verified-static")
    assert n == 0  # no patch_diff -> not verified


def test_verify_findings_records_stage(tmp_path):
    from sec_harness.state import load_state

    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_confirmed("F-0002", "sqli")])
    verify_findings(ws, "t", "c", verifier=lambda *a, **k: "verified-static")
    assert "verify" in load_state(ws).stages


def test_codeql_finding_routes_to_codeql_rerun(monkeypatch):
    import sec_harness.verify as V
    calls = []
    monkeypatch.setattr(V, "run_semgrep",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no semgrep")))
    monkeypatch.setattr(V, "run_codeql", lambda target, **k: calls.append(target) or [])
    V.verify_patch("/tgt", "diff", "cfg", "app.py", "sqli",
                   evidence_sources=["codeql:py/sql-injection"])
    assert calls


def test_copy_ignore_skips_git_and_sockets(tmp_path):
    import os

    from sec_harness.verify import _copy_ignore
    (tmp_path / ".git").mkdir()
    (tmp_path / "app.php").write_text("<?php")
    os.mkfifo(tmp_path / "a.sock")  # named pipe stands in for an uncopyable socket
    skip = _copy_ignore(str(tmp_path), [".git", "app.php", "a.sock"])
    assert ".git" in skip
    assert "a.sock" in skip
    assert "app.php" not in skip


def test_verify_patch_does_not_choke_on_git_dir(tmp_path, monkeypatch):
    # a target containing a .git dir must not crash copytree; .git is skipped.
    import sec_harness.verify as V
    target = tmp_path / "tgt"; (target / ".git").mkdir(parents=True)
    (target / "app.php").write_text("<?php echo 1;")
    calls = {"n": 0}

    def fake_hit(target_dir, config, basename, cls, rules):
        calls["n"] += 1
        return calls["n"] == 1  # flagged pre-patch, gone post-patch

    monkeypatch.setattr(V, "_file_has_hit", fake_hit)
    monkeypatch.setattr(V, "apply_patch", lambda d, p, **k: True)
    out = V.verify_patch(str(target), "diff", "cfg", "app.php", "xss")
    assert out == "verified-static"


def test_verify_matches_specific_rule_not_whole_class(monkeypatch):
    # A file with two crypto-class hits from DIFFERENT rules. The finding's own
    # rule (mcrypt-use) clears after the patch, but a sibling class rule
    # (weak-crypto) still fires. Class-level matching would wrongly say not-fixed;
    # rule-specific matching credits the fix.
    import sec_harness.verify as V
    from sec_harness.models import Finding, FindingStatus, Severity

    def scan_states(state):
        def _run(target_dir, config, **k):
            hits = [Finding(id="s1", rule_id="php.weak-crypto", cls="crypto",
                            status=FindingStatus.CANDIDATE, severity=Severity.LOW,
                            file="Crypter.php", line=5, message="m")]
            if state["pre"]:  # mcrypt-use present only pre-patch
                hits.append(Finding(id="s2", rule_id="php.mcrypt-use", cls="crypto",
                                    status=FindingStatus.CANDIDATE, severity=Severity.LOW,
                                    file="Crypter.php", line=9, message="m"))
            state["pre"] = False  # first call = pre, second = post
            return hits
        return _run

    monkeypatch.setattr(V, "run_semgrep", scan_states({"pre": True}))
    monkeypatch.setattr(V, "apply_patch", lambda d, p, **k: True)
    monkeypatch.setattr(V.shutil, "copytree", lambda *a, **k: None)
    out = V.verify_patch("t", "diff", "cfg", "Crypter.php", "crypto",
                         ["semgrep:php.mcrypt-use", "structural-index:callers"])
    assert out == "verified-static"  # the finding's own rule cleared
