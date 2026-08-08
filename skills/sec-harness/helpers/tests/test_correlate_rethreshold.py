from __future__ import annotations

from pathlib import Path

from sec_harness.correlate.edges import control_enforces_edges
from sec_harness.correlate.ingest import ingest, member_coverage
from sec_harness.correlate.manifest import Manifest, Member
from sec_harness.correlate.rethreshold import rethreshold
from tests.correlate_fixtures import build_member


def _ndt(fid, msg):
    return {"id": fid, "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
            "rule_id": "context:claimed-control", "file": "src/rbac/spec.js", "line": 1,
            "message": msg, "evidence_sources": ["ast-grep:x"]}


def _enf(fid, msg, status="needs-deployment-testing"):
    return {"id": fid, "cls": "authz", "status": status, "severity": "medium",
            "rule_id": "handler-check", "file": "api.go", "line": 9, "message": msg,
            "evidence_sources": ["ast-grep:y"]}


def _members(tmp_path, enf_findings, enf_ledger):
    ma = build_member(tmp_path, slug="rbac-1", scan_scope=".",
                      findings=[_ndt("A-1", "privilege 'p write' unscoped; enforcement out-of-repo")])
    mb = {**build_member(tmp_path, slug="svc-1", scan_scope=".", findings=enf_findings),
          "role": "service-enforcer"}
    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    if enf_ledger is not None:
        from sec_harness.correlate.ingest import member_workspace
        (member_workspace(Member(**mb)).kb / "coverage-ledger.json").write_text(enf_ledger)
    return man


def test_promote_when_enforcer_has_gap_finding(tmp_path: Path):
    man = _members(tmp_path, [_enf("E-1", "handler for 'p write' has no MR check")], None)
    ings = ingest(man); edges = control_enforces_edges(ings); cov = member_coverage(man)
    verdicts = rethreshold(ings, edges, cov)
    v = next(v for v in verdicts if v.finding_ref.startswith("rbac-1#."))
    assert v.direction == "promote"
    assert v.correlated_status == "confirmed"
    assert v.base_status == "needs-deployment-testing"
    assert v.evidence_chain  # non-empty provenance


def test_demote_when_enforcer_ledger_no_issue(tmp_path: Path):
    ledger = ('{"completeness": "complete", "surfaces": [{"id": "authz", "disposition": '
              '"no_issue_found"}], "deferred": [], "open_questions": []}')
    # enforcer carries a token-bearing finding sharing the rbac privilege token so a
    # control-enforces edge forms; the ledger's no_issue_found disposition drives the demote.
    man = _members(tmp_path, [_enf("E-1", "handler for 'p write' has no MR check", status="fixed")],
                   ledger)  # enforcer investigated authz, no issue
    ings = ingest(man); edges = control_enforces_edges(ings); cov = member_coverage(man)
    v = next(v for v in rethreshold(ings, edges, cov) if v.finding_ref.startswith("rbac-1#."))
    assert v.direction == "demote"
    assert v.correlated_status == "rejected"
    assert v.base_status == "needs-deployment-testing"


def test_coverage_gap_when_no_edge(tmp_path: Path):
    ma = build_member(tmp_path, slug="rbac-1", scan_scope=".",
                      findings=[_ndt("A-1", "privilege 'lonely priv' unscoped; enforcement out-of-repo")])
    man = Manifest(product="p", members=[Member(**ma)])  # no enforcer member
    ings = ingest(man); edges = control_enforces_edges(ings); cov = member_coverage(man)
    v = next(v for v in rethreshold(ings, edges, cov) if v.finding_ref.startswith("rbac-1#."))
    assert v.direction == "coverage-gap"
    assert v.correlated_status == "needs-deployment-testing"
