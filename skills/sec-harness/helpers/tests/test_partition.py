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
                        _f(4, "unknown"), _f(5, "deps")])
    out = unrouted_candidate_classes(ws, ["xss", "sqli"])
    assert out == {"security-other": 2, "unknown": 1}  # deps excluded, xss routed
