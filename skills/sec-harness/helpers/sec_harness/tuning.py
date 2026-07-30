"""Adaptive-tuning scoreboard, ratchet, and log.

Deterministic support for the Phase 0.5 tuning loop (Plan 13): summarize a
finding set's signal, decide whether a re-tuned config strictly improved the
CONFIRMED set, and append every round's decision to a durable log.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from sec_harness.evidence import confidence_for, is_tool_receipt
from sec_harness.fingerprint import diff_findings, fingerprint
from sec_harness.models import Finding, FindingStatus
from sec_harness.workspace import Workspace


def signal_snapshot(findings: list[Finding]) -> dict:
    """Summarize a finding set's signal for tuning decisions.

    Args:
        findings: All findings in a workspace after a pipeline run.

    Returns:
        A dict with total/confirmed counts, the sorted fingerprints of confirmed
        findings, tool-receipt coverage (files + classes), and the evidence-grade
        distribution over all findings.
    """
    confirmed = [f for f in findings if f.status is FindingStatus.CONFIRMED]
    covered = [f for f in findings if any(is_tool_receipt(s) for s in f.evidence_sources)]
    grades = Counter(confidence_for(f.evidence_sources).value for f in findings)
    return {
        "total": len(findings),
        "confirmed": len(confirmed),
        "confirmed_fingerprints": sorted(fingerprint(f) for f in confirmed),
        "coverage": {
            "files_with_receipt": len({f.file for f in covered}),
            "classes_covered": sorted({f.cls for f in covered}),
        },
        "evidence": {
            "high": grades.get("high", 0),
            "medium": grades.get("medium", 0),
            "low": grades.get("low", 0),
        },
    }


def is_improvement(best: list[Finding], candidate: list[Finding]) -> bool:
    """Strict ratchet: did the candidate's CONFIRMED set strictly improve?

    True only when the candidate loses no prior confirmed finding, adds at least
    one new confirmed finding, and at least one new confirmed finding carries a
    tool receipt not already present in ``best`` (which *resists* — but does not
    fully eliminate — FP-ladder non-determinism masquerading as a real gain: a
    re-roll that first-confirms a finding from a rule with zero prior confirmed
    findings still presents a "new" receipt; see design spec §7).

    Args:
        best: The current best finding set.
        candidate: The finding set produced by a re-tuned config.

    Returns:
        Whether to accept the candidate (ratchet forward).
    """
    b_conf = [f for f in best if f.status is FindingStatus.CONFIRMED]
    c_conf = [f for f in candidate if f.status is FindingStatus.CONFIRMED]
    d = diff_findings(b_conf, c_conf)
    if d["resolved"]:          # lost a prior confirmed finding
        return False
    if not d["new"]:           # nothing new
        return False
    best_receipts = {s for f in b_conf for s in f.evidence_sources if is_tool_receipt(s)}
    new_fps = set(d["new"])
    for f in c_conf:
        if fingerprint(f) in new_fps and any(
            is_tool_receipt(s) and s not in best_receipts for s in f.evidence_sources
        ):
            return True
    return False


@dataclass
class TuningLog:
    """Append-only JSONL log of tuning-round decisions.

    Attributes:
        ws: Workspace whose KB holds ``tuning_log.jsonl``.
    """

    ws: Workspace

    @property
    def path(self) -> Path:
        """Path to the tuning log within the KB."""
        return self.ws.kb / "tuning_log.jsonl"

    def record(self, round_num: int, config_diff: dict, snapshot: dict, verdict: str) -> None:
        """Append one tuning-round record (never truncates prior rounds).

        Args:
            round_num: 0-indexed tuning round.
            config_diff: The config change tried this round.
            snapshot: The :func:`signal_snapshot` for this round.
            verdict: One of ``baseline``/``accepted``/``reverted``.
        """
        self.ws.kb.mkdir(parents=True, exist_ok=True)
        entry = {"round": round_num, "config_diff": config_diff, "snapshot": snapshot, "verdict": verdict}
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def entries(self) -> list[dict]:
        """Return all recorded round entries in order (empty if none).

        Returns:
            The parsed JSONL records.
        """
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]


def gap_report(findings: list[Finding], attack_surface: list[str]) -> dict:
    """Report which attack-surface classes the current tools do NOT cover.

    A class is "covered" only if at least one finding of that class carries a
    tool receipt (LLM-only findings do not count). Steers the tuner toward the
    uncovered classes.

    Args:
        findings: All findings from the latest pipeline run.
        attack_surface: The profile's attack-surface class keys.

    Returns:
        ``{uncovered_classes, covered_classes, files_with_receipt}`` (sorted lists).
    """
    covered = {f.cls for f in findings if any(is_tool_receipt(s) for s in f.evidence_sources)}
    covered_in_surface = sorted(c for c in attack_surface if c in covered)
    uncovered = sorted(c for c in attack_surface if c not in covered)
    files = {f.file for f in findings if any(is_tool_receipt(s) for s in f.evidence_sources)}
    return {
        "uncovered_classes": uncovered,
        "covered_classes": covered_in_surface,
        "files_with_receipt": len(files),
    }
