"""Cross-repo multi-runs SARIF: one run per member + one correlation run over the verdicts."""

from __future__ import annotations

from sec_harness.correlate.ingest import IngestedFinding
from sec_harness.correlate.rethreshold import CorrelationVerdict
from sec_harness.models import Finding, FindingStatus
from sec_harness.sarif import _SCHEMA, to_sarif

_REPORTABLE = {FindingStatus.CONFIRMED, FindingStatus.FIXED}
_PROMOTE_LEVEL = {"promote": "error"}


def to_correlation_sarif(
    ings: list[IngestedFinding], verdicts: list[CorrelationVerdict]
) -> dict:
    """Build a multi-run SARIF: one run per member + one correlation run.

    Each member key gets a run of its ``confirmed``/``fixed`` findings (empty run
    if none, so coverage is explicit); a final ``sec-harness-correlation`` run
    carries the verdicts — ``promote`` as level ``error``, everything else as
    level ``note``. Deterministic (members sorted, verdicts sorted by
    finding_ref).

    Args:
        ings: All ingested findings.
        verdicts: All correlation verdicts.

    Returns:
        A SARIF 2.1.0 document with one run per member plus a correlation run.
    """
    by_member: dict[str, list[Finding]] = {}
    for i in ings:
        by_member.setdefault(i.member_key, [])
        if i.finding.status in _REPORTABLE:
            by_member[i.member_key].append(i.finding)
    runs = []
    for mk in sorted(by_member):
        runs.append(to_sarif(by_member[mk], tool_name=mk)["runs"][0])
    results = []
    for v in sorted(verdicts, key=lambda x: x.finding_ref):
        level = _PROMOTE_LEVEL.get(v.direction, "note")
        results.append(
            {
                "ruleId": f"correlated-{v.direction}",
                "level": level,
                "message": {
                    "text": f"{v.finding_ref}: {v.base_status} -> "
                    f"{v.correlated_status} ({'; '.join(v.evidence_chain)})"
                },
            }
        )
    runs.append(
        {
            "tool": {"driver": {"name": "sec-harness-correlation", "rules": []}},
            "results": results,
        }
    )
    return {"version": "2.1.0", "$schema": _SCHEMA, "runs": runs}
