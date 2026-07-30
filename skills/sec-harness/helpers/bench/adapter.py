"""Scan adapters — the one seam that lets the benchmark drive different scanners.

``ScanAdapter.scan(repo_path, workspace) -> list[Finding]`` runs a full harness pass
over a cloned repo and returns its confirmed/fixed findings. The benchmark, judge,
and tally are adapter-agnostic, so the SAME corpus grades:
  - the current Claude-Code skill now (``CCSkillAdapter`` — driven by the operator/SDK),
  - the future standalone Go binary later (``BinaryAdapter``),
without changing anything downstream. That is how the migration gets a regression
oracle: run both adapters over the corpus, compare scorecards.
"""

from __future__ import annotations

import subprocess
from typing import Protocol

from sec_harness.models import Finding, FindingStatus
from sec_harness.workspace import Workspace, read_findings


class ScanAdapter(Protocol):
    """A driver that scans a repo and yields the harness's reportable findings."""

    def scan(self, repo_path: str, workspace: Workspace) -> list[Finding]:
        ...


def reportable(ws: Workspace) -> list[Finding]:
    """Read confirmed/fixed findings from a workspace (what the benchmark grades)."""
    return [f for f in read_findings(ws)
            if f.status in (FindingStatus.CONFIRMED, FindingStatus.FIXED)]


class WorkspaceAdapter:
    """Adapter for an ALREADY-scanned workspace — reads its findings, runs no scan.

    Use when a scan already ran (e.g. re-tally a prior run, or grade findings the
    operator produced by driving the CC skill by hand into this workspace).
    """

    def __init__(self, workspace_for):
        # workspace_for: callable(repo_path) -> Workspace with existing findings
        self._workspace_for = workspace_for

    def scan(self, repo_path: str, workspace: Workspace) -> list[Finding]:
        return reportable(self._workspace_for(repo_path))


class BinaryAdapter:
    """Adapter that shells out to a standalone scanner binary (the Go migration).

    The binary must accept ``<argv> --target <repo> --workspace <ws>`` and write the
    standard ``findings/*.json`` into the workspace; we then read the reportable set.
    """

    def __init__(self, argv: list[str], *, runner=subprocess.run):
        self.argv = argv
        self.runner = runner

    def scan(self, repo_path: str, workspace: Workspace) -> list[Finding]:
        workspace.ensure()
        self.runner([*self.argv, "--target", str(repo_path),
                     "--workspace", str(workspace.root)], check=False)
        return reportable(workspace)


class CCSkillAdapter:
    """Placeholder for driving the current Claude-Code skill end to end.

    The skill's agentic phases run inside a Claude-Code/agent session, not a plain
    subprocess, so this adapter is a documented seam rather than a runnable driver in
    this dev-only harness: the operator (or a future Agent-SDK driver) runs the skill
    into ``workspace``; then grade with :class:`WorkspaceAdapter`. Kept so the corpus
    schema and downstream code already speak "adapter".
    """

    def scan(self, repo_path: str, workspace: Workspace) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError(
            "Drive the CC skill into the workspace (operator or Agent-SDK), then grade "
            "with WorkspaceAdapter. A native SDK driver is the next increment.")
