"""Deterministic check: is a finding's ``patch_diff`` actually applied to the real target?

``verify.py`` only ever applies a patch to a throwaway copy to confirm the fix works in
isolation — a ``FIXED`` status means "patch verified there", never "patch is live in the
target repo". Left unstated, that gap has produced a real framing defect: a runtime-test
directive written as if the fix were deployed, when the vulnerability is still live in the
actual target. This module answers the "is it actually applied" question mechanically
(``git apply --check``, read-only) so downstream consumers don't depend on an adversary
catching the mismatch by hand every time.
"""

from __future__ import annotations

import subprocess
from enum import Enum
from pathlib import Path


class PatchStatus(Enum):
    """Result of checking a patch_diff against a target's real working tree."""

    APPLIED = "applied"
    NOT_APPLIED = "not-applied"
    UNKNOWN = "unknown"


def check_patch_applied(
    target: str | Path, patch_diff: str, *, runner=subprocess.run
) -> PatchStatus:
    """Check whether ``patch_diff``'s changes are already present in ``target``.

    Uses ``git apply --check`` (forward and reverse) against the real target's working
    tree — read-only, never writes to or modifies the target.

    Args:
        target: Path to the target repo's working tree.
        patch_diff: Unified diff text (as stored on ``Finding.patch_diff``).
        runner: Injectable subprocess runner (for tests).

    Returns:
        ``APPLIED`` if the diff's changes are already present (reverse-apply succeeds),
        ``NOT_APPLIED`` if the diff still applies cleanly forward, ``UNKNOWN`` if neither
        check succeeds (e.g. the file has diverged since the patch was generated) or
        ``patch_diff`` is empty.
    """
    if not patch_diff or not patch_diff.strip():
        return PatchStatus.UNKNOWN
    reverse = runner(
        ["git", "apply", "--check", "--reverse"],
        cwd=str(target), input=patch_diff, capture_output=True, text=True,
    )
    if reverse.returncode == 0:
        return PatchStatus.APPLIED
    forward = runner(
        ["git", "apply", "--check"],
        cwd=str(target), input=patch_diff, capture_output=True, text=True,
    )
    if forward.returncode == 0:
        return PatchStatus.NOT_APPLIED
    return PatchStatus.UNKNOWN


def not_applied_caution(patch_status: PatchStatus) -> str | None:
    """Caution text for a ``fixed`` finding whose patch isn't confirmed live in the target.

    Args:
        patch_status: Result of :func:`check_patch_applied` for this finding.

    Returns:
        A caution string when the patch is not confirmed applied (``NOT_APPLIED`` or
        ``UNKNOWN``), else ``None`` when it is confirmed ``APPLIED``.
    """
    if patch_status is PatchStatus.APPLIED:
        return None
    return (
        "**Caution:** this finding is `fixed` against a validated patch, but the patch has "
        "NOT been confirmed applied to this target's working tree — `verify.py` only checks "
        "it against a throwaway copy. Treat this as a **live-exploit check** against the "
        "still-vulnerable code, not a regression check on a deployed fix, unless you have "
        "independently confirmed the patch is deployed."
    )
