"""Multi-pass campaign supervision: stage tracking, carry-forward, reporting.

Coordinates the sequence of passes over one persistent workspace. Stage
recording lets ``begin_pass`` advance the pass counter; carry-forward preserves
settled conclusions across passes while re-checking code that changed.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

from sec_harness.models import CampaignState, FindingStatus
from sec_harness.state import load_state, save_state
from sec_harness.workspace import Workspace, read_findings, write_findings


def record_stage(ws: Workspace, stage: str) -> CampaignState:
    """Mark a pipeline stage complete for the current pass.

    Recording at least one stage is what lets the next ``begin_pass`` recognize
    a completed pass and increment ``pass_number``.

    Args:
        ws: Workspace holding campaign state.
        stage: Stage name (e.g. ``"prefilter"``, ``"investigate"``).

    Returns:
        The updated :class:`CampaignState`.
    """
    state = load_state(ws)
    state.stages[stage] = "done"
    save_state(ws, state)
    return state


def pass_report(ws: Workspace) -> dict:
    """Summarize the current pass: state + findings-by-status counts.

    Args:
        ws: Workspace to summarize.

    Returns:
        A dict with ``pass_number``, ``active_sha``, ``stages``, and
        ``findings_by_status``.
    """
    state = load_state(ws)
    counts = Counter(f.status.value for f in read_findings(ws))
    return {
        "pass_number": state.pass_number,
        "active_sha": state.active_sha,
        "stages": dict(state.stages),
        "findings_by_status": dict(counts),
    }


_SETTLED = {FindingStatus.CONFIRMED, FindingStatus.FIXED, FindingStatus.REJECTED}
# Terminal statuses: resume must NOT re-run work that reached one of these (Bucket C4).
# Non-terminal (candidate/raw/stale) are retried on resume.
TERMINAL_STATUSES = {
    FindingStatus.CONFIRMED, FindingStatus.FIXED, FindingStatus.REJECTED,
    FindingStatus.DUPLICATE, FindingStatus.NEEDS_DEPLOYMENT_TESTING,
    FindingStatus.INFORMATIONAL,
}


def salvage_partial(ws: Workspace, agent_error: str, *, statuses=(FindingStatus.RAW,)) -> list[str]:
    """Tag findings written before an agent error as salvaged rather than discarding them.

    dcrh's lesson: if a subagent lands a finding and THEN crashes (max-turns, transient
    error), the finding on disk is real work — keep and grade it, don't lose the batch. This
    stamps a ``salvaged`` history event on non-terminal findings so a resume grades them
    instead of re-deriving from scratch.

    Args:
        ws: Workspace whose findings are stamped in place.
        agent_error: Short description of the error that interrupted the agent.
        statuses: Which finding statuses count as salvageable partial work.

    Returns:
        The ids stamped as salvaged.
    """
    findings = read_findings(ws)
    salvaged: list[str] = []
    for f in findings:
        if f.status in statuses and not any(h.get("event") == "salvaged" for h in f.history):
            f.history.append({"event": "salvaged", "reason": agent_error})
            salvaged.append(f.id)
    if salvaged:
        write_findings(ws, findings)
    return salvaged


def promote_runtime_dependent(ws: Workspace) -> int:
    """Promote raw findings marked runtime_dependent to needs-deployment-testing (O-010/O-021).

    A finding whose only barrier to confirmation is data not in the repo (catalog, live host,
    secret liveness) is a genuine runtime lead — it must reach the red-team plan, not die as raw.

    Args:
        ws: Workspace whose findings are promoted in place.

    Returns:
        The count of findings promoted.
    """
    findings = read_findings(ws)
    n = 0
    for f in findings:
        if f.status is FindingStatus.RAW and f.runtime_dependent:
            f.status = FindingStatus.NEEDS_DEPLOYMENT_TESTING
            f.history.append({"event": "campaign:promoted-runtime-dependent"})
            n += 1
    if n:
        write_findings(ws, findings)
    return n


_LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Gemfile.lock",
    "go.sum", "go.mod", "poetry.lock", "Pipfile.lock", "requirements.txt",
    "Cargo.lock", "composer.lock",
}


def promote_deps(ws: Workspace) -> int:
    """Promote SCA ``deps`` candidates to confirmed with a reachability note.

    A ``deps`` finding carrying a mechanical SCA receipt (an ``evidence_sources`` entry
    beginning ``sca``) provably identifies a vulnerable dependency, so it is confirmed
    deterministically (no investigate agent routes ``deps``). A lockfile-only hit is marked
    ``reachable=False`` (present in the dependency graph but not shown reachable from runtime
    code — a dev/build/transitive dependency until proven otherwise); any other path is marked
    ``reachable=None`` (present, runtime reachability unverified). LLM-only ``deps`` candidates
    are left untouched — the SCA receipt is the ground.

    Args:
        ws: Workspace whose ``deps`` candidates are promoted in place.

    Returns:
        The number of findings promoted.
    """
    from sec_harness.evidence import is_tool_receipt  # local: keep import graph flat
    findings = read_findings(ws)
    n = 0
    dirty = False
    for f in findings:
        if f.status is not FindingStatus.CANDIDATE or f.cls != "deps":
            continue
        if not any(s.startswith("sca") and is_tool_receipt(s) for s in f.evidence_sources):
            continue
        f.status = FindingStatus.CONFIRMED
        lockfile_only = Path(f.file).name in _LOCKFILES
        f.reachability = {
            "reachable": False if lockfile_only else None,
            "blocker": "dev-build-dependency-not-runtime-verified" if lockfile_only else None,
            "chain": [],
        }
        f.history.append({"event": "campaign:promoted-deps", "lockfile_only": lockfile_only})
        n += 1
        dirty = True
    if dirty:
        write_findings(ws, findings)
    return n


def carry_forward(ws: Workspace, changed_files: list[str]) -> dict[str, int]:
    """Carry settled findings across passes, restaling those whose file changed.

    Settled findings (``CONFIRMED``/``FIXED``/``REJECTED``) on files that changed
    since the prior pass are transitioned to ``STALE`` so the next pass
    re-examines them (drift check); settled findings on unchanged files are kept
    as-is (the campaign does not re-litigate stable conclusions). Non-settled
    findings are left untouched.

    Args:
        ws: Workspace whose findings are carried forward in place.
        changed_files: Files changed since the prior pass (any path form; only
            basenames are compared).

    Returns:
        ``{"staled": <count re-staled>, "kept": <count settled+unchanged>}``.
    """
    changed = {os.path.basename(c) for c in changed_files}
    # ponytail: basename match aliases same-named files in different dirs; use
    # full relative paths if a real polyglot repo needs it.
    findings = read_findings(ws)
    staled = kept = 0
    dirty = False
    for f in findings:
        if f.status not in _SETTLED:
            continue
        if os.path.basename(f.file) in changed:
            f.status = FindingStatus.STALE
            f.history.append({"event": "carry_forward:staled(drift)"})
            staled += 1
            dirty = True
        else:
            kept += 1
    if dirty:
        write_findings(ws, findings)
    return {"staled": staled, "kept": kept}
