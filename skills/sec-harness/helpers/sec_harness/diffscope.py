"""Scope incremental passes to changed files via git."""

from __future__ import annotations

import subprocess


def changed_files(base: str, head: str = "HEAD", *, runner=subprocess.run) -> list[str]:
    """Return files changed between two revisions.

    Args:
        base: Base revision (e.g. the prior pass's pinned SHA).
        head: Head revision (default ``HEAD``).
        runner: Injectable subprocess runner (for testing).

    Returns:
        Repo-relative changed file paths.
    """
    completed = runner(
        # `--` separates revisions from paths so a ref that looks like a path can't be misparsed.
        ["git", "diff", "--name-only", base, head, "--"], capture_output=True, text=True, check=False
    )
    return [line for line in completed.stdout.splitlines() if line.strip()]


def head_sha(*, runner=subprocess.run) -> str:
    """Return the current ``HEAD`` commit SHA.

    Args:
        runner: Injectable subprocess runner (for testing).

    Returns:
        The stripped HEAD SHA.
    """
    completed = runner(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return completed.stdout.strip()
