"""Git-history mining (Bucket B2, from audit recon + dcrh "past vulns are a cheat-code").

Past security fixes are leading indicators of the bug CLASS: the fixed pattern usually recurs
in unpatched siblings. This surfaces likely security-fix commits and the files they touched so
recon/context-ingest can seed candidates ("was this fix complete, and applied everywhere?").
Git-only, host-side, injectable runner; never executes the target.
"""

from __future__ import annotations

import subprocess

# Commit-message signals for a security fix (case-insensitive grep alternation).
_SECURITY_GREP = (
    r"CVE-|vuln|security|exploit|injection|traversal|overflow|"
    r"XSS|CSRF|SSRF|RCE|sanitize|escape|auth bypass|privilege"
)


def security_fix_commits(target: str, *, limit: int = 200, runner=subprocess.run) -> list[dict]:
    """Return likely security-fix commits (``{sha, subject}``), newest first, capped at ``limit``.

    Args:
        target: Path to the target git repo.
        limit: Max commits to return.
        runner: Injectable subprocess runner (for testing).
    """
    try:
        completed = runner(
            ["git", "-C", target, "log", f"-n{limit}", "--no-merges",
             "--pretty=%H%x1f%s", f"--grep={_SECURITY_GREP}", "-E", "-i"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return []
    if completed.returncode != 0:
        return []
    out = []
    for line in completed.stdout.splitlines():
        if "\x1f" in line:
            sha, subject = line.split("\x1f", 1)
            out.append({"sha": sha.strip(), "subject": subject.strip()})
    return out


def files_in_commit(target: str, sha: str, *, runner=subprocess.run) -> list[str]:
    """Return the files a commit touched (seeds for sibling hunting)."""
    try:
        completed = runner(
            ["git", "-C", target, "show", "--name-only", "--pretty=format:", sha],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return []
    if completed.returncode != 0:
        return []
    return [ln.strip() for ln in completed.stdout.splitlines() if ln.strip()]
