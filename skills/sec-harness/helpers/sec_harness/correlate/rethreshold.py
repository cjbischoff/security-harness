"""Cross-repo re-thresholding: resolve a finding's out-of-repo barrier using another member.

A ``needs-deployment-testing`` finding's exploitability barrier is "out of repo" only from its own
repo's view. When a ``control-enforces`` edge lands that barrier in an ingested member, that member's
own (adversary-validated) findings + coverage-ledger become the cross-repo receipt: barrier proven
absent/uncovered → promote; the enforcer investigated the class and found no issue → demote
(compensating control); enforcer not in the set → coverage-gap. Sources are never mutated; a
CorrelationVerdict lives only in the correlation workspace and preserves the base status.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sec_harness.correlate.edges import Edge
from sec_harness.correlate.ingest import IngestedFinding

_PROMOTE_ENFORCER_STATUSES = {"confirmed", "needs-deployment-testing"}
_GAP_DISPOSITIONS = {"needs_follow_up", "reported"}


@dataclass
class CorrelationVerdict:
    """A cross-repo re-thresholding verdict for one finding (never written back to the member).

    Attributes:
        finding_ref: Cross-repo id of the source finding.
        base_status: Original status of the finding (always preserved).
        correlated_status: Status after cross-repo resolution.
        direction: One of ``promote``, ``demote``, ``weaken``, or ``coverage-gap``.
        edge: The edge key that drove the verdict, or None.
        evidence_chain: Ordered provenance strings for the verdict.
        confidence: Confidence level (``high``, ``medium``, or ``low``).
    """

    finding_ref: str
    base_status: str
    correlated_status: str
    direction: str                       # promote | demote | weaken | coverage-gap
    edge: str | None
    evidence_chain: list[str] = field(default_factory=list)
    confidence: str = "medium"

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict (evidence_chain sorted for determinism).

        Returns:
            A dictionary representation with sorted evidence_chain.
        """
        d = asdict(self)
        d["evidence_chain"] = sorted(self.evidence_chain)
        return d


def _ledger_disposition(coverage: dict, member_key: str, cls: str) -> str | None:
    """Return the coverage-ledger disposition for ``cls`` in ``member_key`` (or None).

    Args:
        coverage: ``member_key -> coverage-ledger dict`` from :func:`ingest.member_coverage`.
        member_key: The member to look up.
        cls: The finding class to find a surface for.

    Returns:
        The disposition string (e.g. ``no_issue_found``, ``needs_follow_up``), or None.
    """
    for s in coverage.get(member_key, {}).get("surfaces", []):
        if s.get("id") == cls:
            return s.get("disposition")
    return None


def rethreshold(ings: list[IngestedFinding], edges: list[Edge],
                coverage: dict[str, dict]) -> list[CorrelationVerdict]:
    """Produce cross-repo verdicts for every ``needs-deployment-testing`` finding.

    Args:
        ings: All ingested findings.
        edges: All edges (only ``control-enforces`` drive re-thresholding).
        coverage: ``member_key -> coverage-ledger dict`` (:func:`ingest.member_coverage`).

    Returns:
        One :class:`CorrelationVerdict` per needs-deployment-testing finding. Promotion to
        ``confirmed`` requires a ``deterministic`` edge AND an enforcer receipt (a
        confirmed/NDT enforcer finding of the class, or a ``needs_follow_up``/``reported``
        coverage disposition); an enforcer ``no_issue_found`` demotes; no edge → coverage-gap.
        An ``llm``-join edge can only ``weaken`` (never promote).
    """
    by_ref = {i.cross_repo_id: i for i in ings}
    # index control-enforces edges by the rbac-source finding they resolve (detail["from"])
    ce_by_from: dict[str, Edge] = {}
    for e in edges:
        if e.type == "control-enforces":
            ce_by_from.setdefault(e.detail.get("from", ""), e)
    verdicts: list[CorrelationVerdict] = []
    for i in ings:
        if i.finding.status.value != "needs-deployment-testing":
            continue
        e = ce_by_from.get(i.cross_repo_id)
        if e is None:
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="needs-deployment-testing", direction="coverage-gap",
                edge=None, evidence_chain=[], confidence="low"))
            continue
        enforcer_key = e.members[1] if e.members[0] == i.member_key else e.members[-1]
        to_ref = e.detail.get("to", "")
        enforcer = by_ref.get(to_ref)
        cls = e.detail.get("to_cls") or i.finding.cls
        disp = _ledger_disposition(coverage, enforcer_key, cls)
        is_det = e.detail.get("join") == "deterministic"
        barrier_absent = (
            (enforcer is not None and enforcer.finding.status.value in _PROMOTE_ENFORCER_STATUSES)
            or disp in _GAP_DISPOSITIONS
        )
        if disp == "no_issue_found":
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="rejected", direction="demote", edge=e.key,
                evidence_chain=[f"{enforcer_key}: coverage-ledger {cls}=no_issue_found"],
                confidence="medium"))
        elif barrier_absent and is_det:
            chain = [f"{enforcer_key}: {to_ref}"]
            if disp:
                chain.append(f"{enforcer_key}: coverage-ledger {cls}={disp}")
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="confirmed", direction="promote", edge=e.key,
                evidence_chain=chain, confidence="high"))
        elif barrier_absent:  # llm-join edge: weaken only, never promote
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="needs-deployment-testing", direction="weaken", edge=e.key,
                evidence_chain=[f"{enforcer_key}: {to_ref} (llm-join — not receipt-grade)"],
                confidence="low"))
        else:
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="needs-deployment-testing", direction="coverage-gap",
                edge=e.key, evidence_chain=[], confidence="low"))
    return sorted(verdicts, key=lambda v: v.finding_ref)


def write_verdicts(path: str | Path, verdicts: list[CorrelationVerdict]) -> None:
    """Write verdicts to JSON (sorted, deterministic).

    Args:
        path: Output file path.
        verdicts: List of verdicts to serialize.
    """
    Path(path).write_text(json.dumps([v.to_dict() for v in verdicts], indent=2))
