"""Cross-repo multi-runs SARIF builder tests."""

from __future__ import annotations

from sec_harness.correlate.ingest import IngestedFinding
from sec_harness.correlate.rethreshold import CorrelationVerdict
from sec_harness.correlate.xrepo_sarif import to_correlation_sarif
from sec_harness.models import Finding, FindingStatus, Severity


def _f(status: FindingStatus) -> Finding:
    """Create a test Finding with a given status.

    Args:
        status: The FindingStatus value.

    Returns:
        A Finding object for testing.
    """
    return Finding(
        id="F-001",
        rule_id="r",
        cls="authz",
        status=status,
        severity=Severity.HIGH,
        file="h.go",
        line=9,
        message="m",
    )


def test_sarif_one_run_per_member_plus_correlation_run() -> None:
    """Test that SARIF output has one run per member plus a correlation run."""
    ings = [
        IngestedFinding(
            member_key="a#.",
            role="rbac-source",
            cross_repo_id="a#.:h.go:9:r",
            finding=_f(FindingStatus.CONFIRMED),
        ),
        IngestedFinding(
            member_key="b#x",
            role="service-enforcer",
            cross_repo_id="b#x:h.go:9:r",
            finding=_f(FindingStatus.NEEDS_DEPLOYMENT_TESTING),
        ),  # not reportable
    ]
    v = CorrelationVerdict(
        finding_ref="a#.:h.go:9:r",
        base_status="needs-deployment-testing",
        correlated_status="confirmed",
        direction="promote",
        edge="k",
        evidence_chain=["b#x: rcpt"],
        confidence="high",
    )
    doc = to_correlation_sarif(ings, [v])
    names = [r["tool"]["driver"]["name"] for r in doc["runs"]]
    assert names == ["a#.", "b#x", "sec-harness-correlation"]
    assert len(doc["runs"][0]["results"]) == 1  # confirmed finding of member a
    assert doc["runs"][1]["results"] == []  # NDT is not reportable
    corr = doc["runs"][-1]["results"]
    assert corr[0]["level"] == "error" and corr[0]["ruleId"] == "correlated-promote"
    assert "locations" not in corr[0]  # empty locations dropped for GitHub ingest
    assert doc == to_correlation_sarif(ings, [v])  # deterministic


def test_fixed_finding_is_reportable() -> None:
    """A FIXED finding appears in its member's run (FIXED is reportable)."""
    ings = [
        IngestedFinding(
            member_key="a#.",
            role="rbac-source",
            cross_repo_id="a#.:h.go:9:r",
            finding=_f(FindingStatus.FIXED),
        ),
    ]
    doc = to_correlation_sarif(ings, [])
    assert len(doc["runs"][0]["results"]) == 1


def test_demote_verdict_is_note_level() -> None:
    """A non-promote verdict produces a note-level correlation result."""
    v = CorrelationVerdict(
        finding_ref="a#.:h.go:9:r",
        base_status="confirmed",
        correlated_status="rejected",
        direction="demote",
        edge="k",
        evidence_chain=["b#x: rcpt"],
        confidence="high",
    )
    corr = to_correlation_sarif([], [v])["runs"][-1]["results"]
    assert corr[0]["level"] == "note" and corr[0]["ruleId"] == "correlated-demote"
