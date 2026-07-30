"""Knowledge-base (workspace/kb) file paths and profile read/write helpers."""

from __future__ import annotations

from pathlib import Path

from sec_harness.profile import ScanProfile, load_profile, save_profile
from sec_harness.workspace import Workspace


def profile_path(ws: Workspace) -> Path:
    """Path to the scan profile within the KB."""
    return ws.kb / "scan-profile.json"


def architecture_path(ws: Workspace) -> Path:
    """Path to the architecture document within the KB."""
    return ws.kb / "architecture.md"


def threat_model_path(ws: Workspace) -> Path:
    """Path to the threat model document within the KB."""
    return ws.kb / "THREAT_MODEL.md"


def entities_dir(ws: Workspace) -> Path:
    """Directory holding per-component entity notes."""
    return ws.kb / "entities"


def write_profile(ws: Workspace, profile: ScanProfile) -> None:
    """Persist a scan profile into the KB.

    Args:
        ws: Target workspace.
        profile: Profile to write.
    """
    ws.kb.mkdir(parents=True, exist_ok=True)
    save_profile(profile_path(ws), profile)


def read_profile(ws: Workspace) -> ScanProfile:
    """Load and validate the scan profile from the KB.

    Args:
        ws: Source workspace.

    Returns:
        The parsed :class:`ScanProfile`.
    """
    return load_profile(profile_path(ws))


def kb_status(ws: Workspace) -> dict[str, bool]:
    """Report which KB artifacts exist.

    Args:
        ws: Workspace to inspect.

    Returns:
        Presence flags for ``profile``, ``architecture``, ``threat_model``.
    """
    return {
        "profile": profile_path(ws).exists(),
        "architecture": architecture_path(ws).exists(),
        "threat_model": threat_model_path(ws).exists(),
    }
