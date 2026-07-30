"""Upstream-fix novelty check (Bucket B6, from dcrh novelty.py).

Cheap, host-side, git-only: has the file a finding sits in changed upstream since the finding
was discovered? A change since discovery may mean the bug was already fixed — worth telling a
human before they spend runtime effort. Never executes the target; never raises (a git failure
becomes ``UNKNOWN``). Off by default; the caller opts in.
"""

from __future__ import annotations

import subprocess


def upstream_status(target: str, discovery_sha: str | None, file: str,
                    *, runner=subprocess.run) -> str:
    """Return ``FIXED`` / ``UNFIXED`` / ``UNKNOWN`` for a finding's file since ``discovery_sha``.

    ``FIXED`` — the file changed in ``discovery_sha..HEAD`` (a fix may have landed; the caller/
    agent judges whether it addresses this finding). ``UNFIXED`` — no commit touched the file
    since discovery. ``UNKNOWN`` — no SHA, or git errored (never raises).

    Args:
        target: Path to the target git repo.
        discovery_sha: SHA the finding was discovered against.
        file: Repo-relative file the finding sits in.
        runner: Injectable subprocess runner (for testing).
    """
    if not discovery_sha:
        return "UNKNOWN"
    try:
        completed = runner(
            ["git", "-C", target, "log", "--oneline", f"{discovery_sha}..HEAD", "--", file],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return "UNKNOWN"
    if completed.returncode != 0:
        return "UNKNOWN"
    return "FIXED" if completed.stdout.strip() else "UNFIXED"
