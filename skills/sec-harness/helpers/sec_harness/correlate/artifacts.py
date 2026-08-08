"""Combined cross-repo artifacts: deterministic skeletons (diagrams + tables) + narrative markers.

Code owns everything deterministic — the mermaid diagrams and the tables. The combiner agent
(``agents/correlate-combiner.md``) fills only the ``<!-- NARRATIVE: <slot> -->`` markers and must
not edit the code-authored blocks. Nothing here writes to a member repo.
"""

from __future__ import annotations

from sec_harness.correlate.edges import Edge
from sec_harness.correlate.ingest import IngestedFinding
from sec_harness.correlate.manifest import Manifest
from sec_harness.correlate.mermaid import attack_chain_graph, component_graph
from sec_harness.correlate.rethreshold import CorrelationVerdict
from sec_harness.correlate.workspace import CorrelationWorkspace


def _table(header: list[str], rows: list[list[str]]) -> str:
    """Render a deterministic GitHub-flavored markdown table.

    Args:
        header: Column headers.
        rows: Row cells (already sorted by the caller).

    Returns:
        The markdown table, or an italic ``_none_`` line if there are no rows.
    """
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(c.replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def _mermaid(diagram: str) -> str:
    """Wrap a diagram in mermaid markdown fencing.

    Args:
        diagram: The diagram source.

    Returns:
        The fenced mermaid block.
    """
    return f"```mermaid\n{diagram.rstrip()}\n```\n"


def _marker(slot: str) -> str:
    """Create a narrative marker for the combiner agent.

    Args:
        slot: The slot name.

    Returns:
        The HTML comment marker.
    """
    return f"<!-- NARRATIVE: {slot} -->\n"


def build_artifacts(
    manifest: Manifest,
    ings: list[IngestedFinding],
    edges: list[Edge],
    verdicts: list[CorrelationVerdict],
) -> dict[str, str]:
    """Build the four combined artifact docs (deterministic; diagrams + tables + markers).

    Args:
        manifest: The product manifest.
        ings: All ingested findings (drives the per-member finding summary in FINDINGS.md).
        edges: All cross-repo edges.
        verdicts: All correlation verdicts.

    Returns:
        ``{filename: markdown}`` for ARCHITECTURE / THREAT_MODEL / REDTEAM / FINDINGS.
    """
    roster = _table(
        ["member_key", "role", "repo_root"],
        sorted([[m.member_key, m.role, m.repo_root] for m in manifest.members]),
    )
    arch = (
        f"# {manifest.product} — Cross-Repo Architecture\n\n"
        + _mermaid(component_graph(manifest, edges))
        + "\n## Members\n\n"
        + roster
        + "\n"
        + _marker("architecture")
    )

    span_rows = sorted(
        [
            [v.finding_ref, v.correlated_status, "; ".join(sorted(v.evidence_chain))]
            for v in verdicts
            if v.direction in ("promote", "weaken", "demote")
        ]
    )
    threat = (
        f"# {manifest.product} — Cross-Repo Threat Model\n\n"
        + _mermaid(attack_chain_graph(verdicts, edges))
        + "\n## Cross-repo re-thresholded findings\n\n"
        + _table(["finding", "correlated_status", "evidence"], span_rows)
        + "\n"
        + _marker("threat-model")
    )

    rt_rows = sorted(
        [
            [v.finding_ref, v.direction, "; ".join(sorted(v.evidence_chain))]
            for v in verdicts
            if v.direction in ("promote", "weaken")
        ]
    )
    redteam = (
        f"# {manifest.product} — Cross-Repo Red-Team Directives\n\n"
        + _table(["finding", "direction", "evidence_chain"], rt_rows)
        + "\n"
        + _marker("redteam")
    )

    verdict_rows = sorted(
        [[v.direction, v.finding_ref, v.base_status, v.correlated_status] for v in verdicts]
    )
    gap_rows = sorted([[v.finding_ref] for v in verdicts if v.direction == "coverage-gap"])
    cve_rows = sorted(
        [[e.key, ", ".join(sorted(e.members))] for e in edges if e.type == "shared-dependency"]
    )
    summary: dict[str, dict[str, int]] = {}
    for i in ings:
        counts = summary.setdefault(i.member_key, {"confirmed": 0, "needs-deployment-testing": 0})
        status = i.finding.status.value
        if status in counts:
            counts[status] += 1
    member_rows = [
        [
            mk,
            str(c["confirmed"]),
            str(c["needs-deployment-testing"]),
            str(c["confirmed"] + c["needs-deployment-testing"]),
        ]
        for mk, c in sorted(summary.items())
    ]
    findings = (
        f"# {manifest.product} — Correlated Findings\n\n## Verdicts\n\n"
        + _table(["direction", "finding", "base_status", "correlated_status"], verdict_rows)
        + "\n## Per-member finding summary\n\n"
        + _table(["member", "confirmed", "needs-deployment-testing", "total"], member_rows)
        + "\n## Coverage gaps (enforcer repo not ingested)\n\n"
        + _table(["finding"], gap_rows)
        + "\n## Shared dependency vulnerabilities\n\n"
        + _table(["osv", "members"], cve_rows)
        + "\n"
        + _marker("findings")
    )

    return {
        "ARCHITECTURE.md": arch,
        "THREAT_MODEL.md": threat,
        "REDTEAM.md": redteam,
        "FINDINGS.md": findings,
    }


def write_artifacts(cw: CorrelationWorkspace, docs: dict[str, str]) -> None:
    """Write the artifact docs under the correlation workspace's artifacts dir.

    Args:
        cw: The correlation workspace.
        docs: ``{filename: markdown}`` from :func:`build_artifacts`.

    Raises:
        FileNotFoundError: If cw.artifacts_dir does not exist (call cw.ensure() first).
    """
    for name, text in sorted(docs.items()):
        (cw.artifacts_dir / name).write_text(text)
