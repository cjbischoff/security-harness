from __future__ import annotations

from pathlib import Path

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.partition import partition_candidates_by_class
from sec_harness.workspace import Workspace, write_findings


def _f(i, cls):
    return Finding(
        id=f"C-{i:04d}",
        rule_id="r",
        cls=cls,
        status=FindingStatus.CANDIDATE,
        severity=Severity.LOW,
        file="a.js",
        line=i,
        message="m",
        evidence="",
        evidence_sources=[],
    )


def test_partition_groups_and_sorts(tmp_path):
    ws = Workspace(tmp_path)
    ws.ensure()
    write_findings(ws, [_f(3, "xss"), _f(1, "sqli"), _f(2, "xss")])
    part = partition_candidates_by_class(ws)
    assert set(part) == {"xss", "sqli"}
    assert [f.id for f in part["xss"]] == ["C-0002", "C-0003"]
    assert [f.id for f in part["sqli"]] == ["C-0001"]


def test_unrouted_candidate_classes(tmp_path):
    from sec_harness.partition import unrouted_candidate_classes
    ws = Workspace(tmp_path)
    ws.ensure()
    write_findings(ws, [_f(1, "xss"), _f(2, "security-other"), _f(3, "security-other"),
                        _f(4, "unknown")])
    out = unrouted_candidate_classes(ws, ["xss", "sqli"])
    assert out == {"security-other": 2, "unknown": 1}  # xss routed


def test_unrouted_candidate_classes_flags_untriaged_deps(tmp_path):
    # Regression for a false-negative trap: deps candidates are not exempt by class name
    # alone — an untriaged one (still status=="candidate") must surface here, since nothing
    # else guarantees an SCA triage mechanism actually ran on it (harness defect 6).
    from sec_harness.partition import unrouted_candidate_classes
    ws = Workspace(tmp_path)
    ws.ensure()
    write_findings(ws, [_f(1, "xss"), _f(2, "deps")])
    out = unrouted_candidate_classes(ws, ["xss"])
    assert out == {"deps": 1}


def test_unrouted_candidate_classes_triaged_deps_not_flagged(tmp_path):
    # Once a deps candidate has been triaged (status changed away from "candidate" by whatever
    # process handled it), it correctly stops appearing here.
    from sec_harness.partition import unrouted_candidate_classes
    ws = Workspace(tmp_path)
    ws.ensure()
    f = _f(1, "deps")
    f.status = FindingStatus.REJECTED
    write_findings(ws, [f])
    out = unrouted_candidate_classes(ws, [])
    assert out == {}


def test_demote_noise_moves_only_noise_candidates(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.partition import demote_noise
    from sec_harness.workspace import Workspace, read_findings, write_findings
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    def c(id_, cls): return Finding(id=id_, rule_id="r", cls=cls, status=FindingStatus.CANDIDATE,
                                    severity=Severity.LOW, file="a.py", line=1, message="m")
    write_findings(ws, [c("C-1", "log-injection"), c("C-2", "sqli"), c("C-3", "clear-text-logging")])
    assert demote_noise(ws) == 2
    by = {f.id: f.status for f in read_findings(ws)}
    assert by["C-1"] is FindingStatus.INFORMATIONAL
    assert by["C-3"] is FindingStatus.INFORMATIONAL
    assert by["C-2"] is FindingStatus.CANDIDATE   # real class untouched
    assert demote_noise(ws) == 0   # idempotent: nothing left to demote


def test_demote_noise_routes_high_severity_unknown_to_security_other(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.partition import demote_noise
    from sec_harness.workspace import Workspace, read_findings, write_findings
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    f = Finding(id="C-1", rule_id="js/insufficient-password-hash", cls="unknown",
                status=FindingStatus.CANDIDATE, severity=Severity.HIGH,
                file="a.py", line=1, message="m")
    write_findings(ws, [f])
    demote_noise(ws)
    got = read_findings(ws)[0]
    assert got.status is FindingStatus.CANDIDATE      # not demoted
    assert got.cls == "security-other"                # rerouted


def test_reconcile_plan_adds_real_unrouted_classes(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.partition import reconcile_plan
    from sec_harness.workspace import Workspace, write_findings
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    def c(id_, cls): return Finding(id=id_, rule_id="r", cls=cls, status=FindingStatus.CANDIDATE,
                                    severity=Severity.LOW, file="a.py", line=1, message="m")
    write_findings(ws, [c("C-1", "sqli"), c("C-2", "log-injection"), c("C-3", "deps"), c("C-4", "authz")])
    out = reconcile_plan(ws, ["authz"])   # recon only planned authz; sqli is a real unrouted class
    assert "sqli" in out and "authz" in out
    assert "log-injection" not in out and "deps" not in out   # noise + deps not routed


def test_reconcile_plan_skips_class_with_no_live_candidates(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.partition import reconcile_plan
    from sec_harness.workspace import Workspace, write_findings
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    def c(id_, cls, status): return Finding(id=id_, rule_id="r", cls=cls, status=status,
                                            severity=Severity.LOW, file="a.py", line=1, message="m")
    write_findings(ws, [c("C-1", "ssrf", FindingStatus.CONFIRMED)])   # settled, no live candidates
    out = reconcile_plan(ws, ["authz"])
    assert "ssrf" not in out   # already-settled class not re-routed on a multi-pass run


def test_reconcile_plan_dedupes_input(tmp_path: Path):
    from sec_harness.partition import reconcile_plan
    from sec_harness.workspace import Workspace
    ws = Workspace(tmp_path); ws.ensure()  # no candidates -> no extras
    out = reconcile_plan(ws, ["authz", "secrets", "authz"])
    assert out == ["authz", "secrets"], "duplicate planned class must appear once"


def test_must_investigate_true_when_classes_exist_even_at_zero_candidates():
    from typing import ClassVar

    from sec_harness.partition import must_investigate

    class P:
        agents_to_spawn: ClassVar = ["business-logic"]

    class Q:
        agents_to_spawn: ClassVar = []

    assert must_investigate(P()) is True     # 0 candidates but a hunt-list class exists -> must run
    assert must_investigate(Q()) is False
