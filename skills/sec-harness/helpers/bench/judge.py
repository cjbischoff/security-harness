"""Judge: did the scan detect a ground-truth positive / wrongly flag a negative?

Deterministic-first (we emit structured findings, unlike VulnHunter's README-only
judge): match on class + file basename + line-proximity + fingerprint. Only fall to
an injected LLM judge for fuzzy class/root-cause matches (e.g. a shallower finding
whose fix would also prevent the ground-truth bug).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from sec_harness.models import Finding

_LINE_WINDOW = 12  # a detection within N lines of the labelled line counts as located


@dataclass
class JudgeResult:
    """Outcome for one corpus entry."""

    finding_id: str
    kind: str          # positive | negative
    source: str
    cls: str
    detected: bool     # positive: found it; negative: WRONGLY flagged it (a false positive)
    method: str        # deterministic | llm | none
    matched_id: str | None
    reasoning: str

    @property
    def is_correct(self) -> bool:
        """A positive is correct when detected; a negative when NOT flagged."""
        return self.detected if self.kind == "positive" else (not self.detected)


def _same_file(entry_file: str, finding_file: str) -> bool:
    return bool(entry_file) and os.path.basename(entry_file) == os.path.basename(finding_file)


def deterministic_match(entry, findings: list[Finding]) -> Finding | None:
    """Return a scan finding that mechanically matches the entry, or None.

    Match = same fingerprint, OR (same class AND same file basename AND line within
    ``_LINE_WINDOW``). For dep-cve entries, match by CVE id appearing in the finding.

    Args:
        entry: A :class:`bench.corpus.CorpusEntry`.
        findings: The scan's findings.

    Returns:
        The first matching finding, or None.
    """
    if entry.source == "dep-cve" and entry.cve:
        for f in findings:
            if entry.cve in (f.rule_id or "") or entry.cve in (f.message or ""):
                return f
        return None
    for f in findings:
        if entry.fingerprint and getattr(f, "fingerprint", None) == entry.fingerprint:
            return f
    for f in findings:
        if f.cls == entry.cls and _same_file(entry.file, f.file) and abs(f.line - entry.line) <= _LINE_WINDOW:
            return f
    return None


def judge_entry(entry, findings: list[Finding], *, llm_judge=None) -> JudgeResult:
    """Judge one entry against a scan's findings.

    Args:
        entry: The ground-truth :class:`bench.corpus.CorpusEntry`.
        findings: The scan's confirmed findings.
        llm_judge: Optional ``callable(entry, findings) -> (detected: bool, reason: str)``
            used ONLY when deterministic matching finds nothing — for fuzzy
            class/root-cause credit. If None, deterministic verdict stands.

    Returns:
        A :class:`JudgeResult`.
    """
    m = deterministic_match(entry, findings)
    if m is not None:
        return JudgeResult(entry.finding_id, entry.kind, entry.source, entry.cls,
                           detected=True, method="deterministic", matched_id=m.id,
                           reasoning=f"deterministic match on {m.cls} @ {m.file}:{m.line}")
    if llm_judge is not None:
        detected, reason = llm_judge(entry, findings)
        return JudgeResult(entry.finding_id, entry.kind, entry.source, entry.cls,
                           detected=bool(detected), method="llm", matched_id=None,
                           reasoning=reason)
    return JudgeResult(entry.finding_id, entry.kind, entry.source, entry.cls,
                       detected=False, method="none", matched_id=None,
                       reasoning="no deterministic match; no LLM judge configured")


def judge_all(entries, findings_by_repo: dict, *, llm_judge=None) -> list[JudgeResult]:
    """Judge every entry against the findings from ITS repo scan.

    Args:
        entries: Iterable of corpus entries.
        findings_by_repo: ``{(repo_url, commit): [Finding, ...]}`` from the scans.
        llm_judge: Optional fuzzy-match fallback.

    Returns:
        One :class:`JudgeResult` per entry.
    """
    out = []
    for e in entries:
        findings = findings_by_repo.get(e.repo_key, [])
        out.append(judge_entry(e, findings, llm_judge=llm_judge))
    return out
