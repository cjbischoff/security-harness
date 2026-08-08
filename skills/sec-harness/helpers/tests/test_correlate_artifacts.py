from sec_harness.correlate.artifacts import build_artifacts, write_artifacts
from sec_harness.correlate.edges import Edge
from sec_harness.correlate.ingest import IngestedFinding
from sec_harness.correlate.manifest import Manifest, Member
from sec_harness.correlate.rethreshold import CorrelationVerdict
from sec_harness.correlate.workspace import CorrelationWorkspace
from sec_harness.models import Finding, FindingStatus, Severity


def _ing():
    f = Finding(id="a", rule_id="r", cls="c", status=FindingStatus.CONFIRMED,
                severity=Severity.HIGH, file="a", line=1, message="m")
    return IngestedFinding(member_key="rbac#.", role="rbac-source",
                           cross_repo_id="rbac#.:a:1:r", finding=f)


def _inputs():
    m = Manifest(product="p", members=[
        Member(slug="rbac", repo_root="/r", scan_scope=".", role="rbac-source"),
        Member(slug="svc", repo_root="/s", scan_scope="x", role="service-enforcer")])
    edges = [Edge(type="shared-dependency", members=["rbac#.", "svc#x"], key="GHSA-1",
                  detail={"reachability": {}})]
    promoted = CorrelationVerdict(finding_ref="rbac#.:a:1:r", base_status="needs-deployment-testing",
                                  correlated_status="confirmed", direction="promote", edge="k",
                                  evidence_chain=["svc#x: receipt"], confidence="high")
    gap = CorrelationVerdict(finding_ref="rbac#.:b:2:r", base_status="needs-deployment-testing",
                             correlated_status="needs-deployment-testing", direction="coverage-gap",
                             edge=None, evidence_chain=[], confidence="low")
    return m, [_ing()], edges, [promoted, gap]


def test_build_artifacts_has_four_docs_with_diagrams_and_markers():
    docs = build_artifacts(*_inputs())
    assert set(docs) == {"ARCHITECTURE.md", "THREAT_MODEL.md", "REDTEAM.md", "FINDINGS.md"}
    assert "```mermaid" in docs["ARCHITECTURE.md"] and "flowchart" in docs["ARCHITECTURE.md"]
    assert "```mermaid" in docs["THREAT_MODEL.md"]
    for name, slot in [("ARCHITECTURE.md", "architecture"), ("THREAT_MODEL.md", "threat-model"),
                       ("REDTEAM.md", "redteam"), ("FINDINGS.md", "findings")]:
        assert f"<!-- NARRATIVE: {slot} -->" in docs[name]


def test_findings_lists_coverage_gap_and_shared_cve():
    docs = build_artifacts(*_inputs())
    assert "rbac#.:b:2:r" in docs["FINDINGS.md"]      # coverage-gap finding listed
    assert "GHSA-1" in docs["FINDINGS.md"]            # shared-CVE rollup
    assert "rbac#.:a:1:r" in docs["REDTEAM.md"]       # promote directive present


def test_findings_has_per_member_summary():
    docs = build_artifacts(*_inputs())
    summary = docs["FINDINGS.md"].split("## Per-member finding summary")[1]
    assert "rbac#." in summary and "| rbac#. | 1 |" in summary  # member_key + confirmed count


def test_write_artifacts_writes_under_artifacts_dir(tmp_path):
    cw = CorrelationWorkspace(tmp_path)
    cw.ensure()
    write_artifacts(cw, build_artifacts(*_inputs()))
    assert (cw.artifacts_dir / "FINDINGS.md").is_file()
