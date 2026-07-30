"""Load/save campaign state and advance passes."""

from __future__ import annotations

import json

from sec_harness.models import CampaignState
from sec_harness.workspace import Workspace


def load_state(ws: Workspace) -> CampaignState:
    """Load campaign state, or a fresh pass-1 state if none exists.

    Args:
        ws: Workspace to read from.

    Returns:
        The persisted or default :class:`CampaignState`.
    """
    if ws.state_path.exists():
        return CampaignState.from_dict(json.loads(ws.state_path.read_text()))
    return CampaignState(pass_number=1, active_sha=None, stages={}, budget={})


def save_state(ws: Workspace, state: CampaignState) -> None:
    """Persist campaign state to the workspace.

    Args:
        ws: Workspace to write to.
        state: State to persist.
    """
    ws.ensure()
    ws.state_path.write_text(json.dumps(state.to_dict(), indent=2))


def begin_pass(ws: Workspace, sha: str | None) -> CampaignState:
    """Begin a new pass, incrementing the counter if the prior pass ran.

    Args:
        ws: Workspace.
        sha: Git SHA to pin for this pass.

    Returns:
        The state for the new (or first) pass, already saved.
    """
    state = load_state(ws)
    if state.stages:
        state.pass_number += 1
        state.stages = {}
    state.active_sha = sha
    save_state(ws, state)
    return state
