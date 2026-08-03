"""Loop-until-dry discovery saturation ledger (kb/discovery-ledger.json).

Drives a bounded convergence loop over discovery waves: keep hunting until K
consecutive waves add zero new candidate fingerprints ("saturated") or a wave cap is
hit ("capped"). State is a plain dict persisted under kb/ — never on the frozen
CampaignState.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_K = 2
DEFAULT_MAX_WAVES = 5
_TERMINALS = (None, "saturated", "capped")


def new_ledger(k: int = DEFAULT_K, max_waves: int = DEFAULT_MAX_WAVES) -> dict:
    """Return a fresh saturation ledger.

    Args:
        k: Consecutive no-new waves required to declare saturation.
        max_waves: Hard cap on total waves.

    Returns:
        A ledger dict with empty ``waves``/``seen`` and no terminal reason.
    """
    return {"k": k, "max_waves": max_waves, "waves": [], "seen": [],
            "consecutive_no_new": 0, "terminal_reason": None}


def _terminal(ledger: dict) -> str | None:
    if ledger["consecutive_no_new"] >= ledger["k"]:
        return "saturated"
    if len(ledger["waves"]) >= ledger["max_waves"]:
        return "capped"
    return None


def record_wave(ledger: dict, fingerprints: list[str]) -> dict:
    """Fold one discovery wave's candidate fingerprints into the ledger in place.

    Args:
        ledger: The ledger to update.
        fingerprints: Candidate fingerprints produced by this wave.

    Returns:
        The updated ledger (also mutated in place).
    """
    seen = set(ledger["seen"])
    fresh = {fp for fp in fingerprints if fp not in seen}
    ledger["waves"].append({"total": len(fingerprints), "new": len(fresh)})
    ledger["consecutive_no_new"] = 0 if fresh else ledger["consecutive_no_new"] + 1
    ledger["seen"] = sorted(seen | set(fingerprints))
    ledger["terminal_reason"] = _terminal(ledger)
    return ledger


def is_terminal(ledger: dict) -> bool:
    """True when the loop has reached ``saturated`` or ``capped``."""
    return ledger["terminal_reason"] is not None


def save_ledger(ws, ledger: dict) -> Path:
    """Persist the ledger to ``kb/discovery-ledger.json`` and return the path."""
    ws.kb.mkdir(parents=True, exist_ok=True)
    path = ws.kb / "discovery-ledger.json"
    path.write_text(json.dumps(ledger, indent=2))
    return path


def load_ledger(ws) -> dict:
    """Load the ledger from ``kb/discovery-ledger.json``."""
    return json.loads((ws.kb / "discovery-ledger.json").read_text())


def validate_discovery_ledger(d: dict) -> list[str]:
    """Validate a discovery ledger; empty list == valid.

    Args:
        d: The ledger to validate.

    Returns:
        A list of human-readable error strings (empty when valid).
    """
    if not isinstance(d, dict):
        return ["discovery-ledger must be an object"]
    errs: list[str] = []
    for key in ("k", "max_waves"):
        if not isinstance(d.get(key), int) or d.get(key, 0) < 1:
            errs.append(f"discovery-ledger.{key} must be a positive integer")
    if not isinstance(d.get("waves"), list):
        errs.append("discovery-ledger.waves must be a list")
    if d.get("terminal_reason") not in _TERMINALS:
        errs.append("discovery-ledger.terminal_reason must be null|saturated|capped")
    return errs
