"""Group workspace candidates by attack class for parallel investigate fan-out."""

from __future__ import annotations

from collections import defaultdict

from sec_harness.models import Finding
from sec_harness.workspace import Workspace, read_findings


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
