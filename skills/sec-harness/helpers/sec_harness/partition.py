"""Group workspace candidates by attack class for parallel investigate fan-out."""

from __future__ import annotations

from collections import defaultdict

from sec_harness.clsmap import is_noise_class
from sec_harness.models import Finding, FindingStatus
from sec_harness.workspace import Workspace, read_findings, write_findings


def partition_candidates_by_class(ws: Workspace) -> dict[str, list[Finding]]:
    """Group a workspace's findings by ``cls`` (values sorted by id).

    Args:
        ws: Workspace to read findings from.

    Returns:
        Mapping of attack-class key to its findings, each list sorted by id.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in read_findings(ws):
        groups[f.cls].append(f)
    return {cls: sorted(fs, key=lambda f: f.id) for cls, fs in groups.items()}


def unrouted_candidate_classes(ws: Workspace, agents_to_spawn: list[str]) -> dict[str, int]:
    """Candidate classes that no investigate agent will own, with their counts.

    A candidate whose ``cls`` is not in ``agents_to_spawn`` (and is not ``deps``,
    which SCA handles) gets no investigate agent under the one-agent-per-spawned-
    class dispatch — it is silently dropped from triage. The classifier routinely
    produces such classes (``security-other``/``unknown`` for vendored rules with
    no ``cls``/CWE), and they can hold high-value hits. The orchestrator should
    surface this and spawn a general-triage agent for the leftovers.

    Args:
        ws: Workspace to read candidates from.
        agents_to_spawn: The profile's ``agents_to_spawn`` list.

    Returns:
        ``{cls: candidate_count}`` for each unrouted class (empty if all routed).
    """
    routed = set(agents_to_spawn) | {"deps"}
    out: dict[str, int] = {}
    for cls, fs in partition_candidates_by_class(ws).items():
        if cls in routed:
            continue
        n = sum(1 for f in fs if f.status.value == "candidate")
        if n:
            out[cls] = n
    return out


def demote_noise(ws: Workspace) -> int:
    """Demote candidate findings in a NOISE_CLASS to INFORMATIONAL (they never enter the FP ladder).

    Args:
        ws: Workspace to read and (if any were demoted) rewrite findings for.

    Returns:
        The number of findings demoted.
    """
    findings = read_findings(ws)
    n = 0
    for f in findings:
        if f.status is FindingStatus.CANDIDATE and is_noise_class(f.cls):
            f.status = FindingStatus.INFORMATIONAL
            f.history.append({"event": "partition:demoted-noise", "cls": f.cls})
            n += 1
    if n:
        write_findings(ws, findings)
    return n


def reconcile_plan(ws: Workspace, agents_to_spawn: list[str]) -> list[str]:
    """Augment ``agents_to_spawn`` with real-security candidate classes recon omitted (O-025).

    Args:
        ws: Workspace to read candidates from.
        agents_to_spawn: The profile's planned ``agents_to_spawn`` list.

    Returns:
        ``agents_to_spawn`` followed by any additional real-security classes present
        among candidates, sorted. Never removes a planned class. Only adds a class
        with at least one live CANDIDATE finding — a class whose findings already
        settled (confirmed/rejected/stale on a later pass) is not re-routed.
    """
    parts = partition_candidates_by_class(ws)
    extra = sorted(
        cls for cls, fs in parts.items()
        if cls not in agents_to_spawn and cls != "deps" and not is_noise_class(cls)
        and any(f.status is FindingStatus.CANDIDATE for f in fs)
    )
    return list(agents_to_spawn) + extra
