"""Static patch verification: apply a fix to a copy, re-scan, confirm it's gone.

The target is never executed and never modified in place — patches apply to a
temp copy, then the configured SAST re-runs on the copy. A finding is only
verified when the scanner flagged its class before the patch and no longer does
after.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


def _copy_ignore(directory: str, names: list[str]) -> set[str]:
    """copytree ignore: skip ``.git`` and any non-regular entry (socket/fifo).

    ``git apply`` patches plain files and does not need a ``.git`` dir, so copying
    it is pure cost — and a live repo's ``.git`` can contain sockets (e.g. the
    fsmonitor ``fsmonitor--daemon.ipc`` IPC socket) that ``copytree`` cannot copy,
    which would crash the whole verify phase. Skipping ``.git`` avoids that and
    speeds the copy; the socket/fifo guard is defensive for any elsewhere.

    Args:
        directory: Directory being copied.
        names: Entry names within it.

    Returns:
        The subset of ``names`` to skip.
    """
    skip: set[str] = set()
    for n in names:
        if n == ".git":
            skip.add(n)
            continue
        try:
            mode = os.lstat(os.path.join(directory, n)).st_mode
        except OSError:
            continue
        if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode):
            skip.add(n)
    return skip

from sec_harness.models import FindingStatus
from sec_harness.sast import run_semgrep
from sec_harness.workspace import Workspace, read_findings, write_findings


def apply_patch(directory: str | Path, patch_diff: str, *, runner=subprocess.run) -> bool:
    """Apply a unified diff inside ``directory`` using ``git apply``.

    Args:
        directory: Directory to apply the patch in (a throwaway copy).
        patch_diff: Unified diff text (paths relative, ``a/`` ``b/`` prefixes).
        runner: Injectable subprocess runner (for testing).

    Returns:
        True if ``git apply`` succeeded.
    """
    directory = Path(directory)
    patch_file = directory / ".sec_harness.patch"
    patch_file.write_text(patch_diff)
    try:
        result = runner(
            ["git", "apply", str(patch_file)],
            cwd=str(directory),
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        if patch_file.exists():
            patch_file.unlink()
    return result.returncode == 0


def _semgrep_rules(evidence_sources: list[str] | None) -> set[str]:
    """Extract the finding's own semgrep rule ids from its evidence sources.

    Lets verification match the SPECIFIC rule that flagged the finding rather
    than the whole attack class — so a fix is credited when *that* signal clears,
    not falsely marked unfixed because an unrelated same-class lint still fires
    in the file (and not falsely credited when a sibling rule of the class is
    what actually went away).

    Args:
        evidence_sources: The finding's ``evidence_sources`` (may be None/empty).

    Returns:
        The set of ``<rule>`` ids from ``semgrep:<rule>`` receipts (empty if none).
    """
    out: set[str] = set()
    for s in evidence_sources or []:
        if s.startswith("semgrep:"):
            out.add(s.split(":", 1)[1])
    return out


def _file_has_hit(
    target_dir: str, config: str, file_basename: str, cls: str, rules: set[str]
) -> bool:
    """Return True if the finding's signal is present in ``file_basename``.

    Matches on the finding's own semgrep rule ids when known (``rules``); falls
    back to attack-class match when the finding carries no semgrep receipt.

    Args:
        target_dir: Directory to scan.
        config: SAST rules config path.
        file_basename: Base filename to match (e.g. ``app.py``).
        cls: Attack-class key (fallback matcher).
        rules: The finding's own semgrep rule ids (precise matcher); empty → class.

    Returns:
        Whether at least one matching finding exists.
    """
    for f in run_semgrep(target_dir, config):
        if os.path.basename(f.file) != file_basename:
            continue
        if f.rule_id in rules if rules else f.cls == cls:
            return True
    return False


def verify_patch(
    target: str, patch_diff: str, config: str, file: str, cls: str,
    evidence_sources: list[str] | None = None,
) -> str:
    """Statically verify a patch neutralizes a finding's class in a file.

    Copies ``target`` to a temp dir, applies the patch, re-runs the SAST, and
    compares the pre/post presence of a ``cls`` hit in ``file``. The original
    ``target`` is never modified.

    Args:
        target: Path to the (unmodified) target repo.
        patch_diff: Unified diff proposed for the finding.
        config: SAST rules config path.
        file: Finding's file path (only the basename is matched).
        cls: Finding's attack class.

    Returns:
        ``"verified-static"`` (was flagged, now gone), ``"not-fixed"`` (still
        flagged after a clean apply), or ``"static-only"`` (not SAST-detectable
        pre-patch, or the patch failed to apply — cannot auto-verify).
    """
    basename = os.path.basename(file)
    rules = _semgrep_rules(evidence_sources)
    # ponytail: basename match is fine for distinct filenames; a repo with two
    # same-named files in different dirs could alias — revisit with full paths then.
    if not _file_has_hit(target, config, basename, cls, rules):
        return "static-only"

    tmp = tempfile.mkdtemp(prefix="sec-harness-verify-")
    try:
        repo = Path(tmp) / "repo"
        shutil.copytree(target, repo, ignore=_copy_ignore)
        if not apply_patch(repo, patch_diff):
            return "static-only"
        still = _file_has_hit(str(repo), config, basename, cls, rules)
        return "not-fixed" if still else "verified-static"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verify_findings(ws: Workspace, target: str, config: str, *, verifier=verify_patch) -> int:
    """Verify patches on confirmed findings and promote verified ones to fixed.

    For each ``CONFIRMED`` finding with a ``patch_diff``, run the verifier and
    record ``verification``; ``verified-static`` results become ``FIXED``.

    Args:
        ws: Workspace whose confirmed findings are verified in place.
        target: Path to the (unmodified) target repo.
        config: SAST rules config path.
        verifier: Injectable verify function (defaults to :func:`verify_patch`).

    Returns:
        The number of findings promoted to ``fixed``.
    """
    findings = read_findings(ws)
    fixed = 0
    changed = False
    for f in findings:
        if f.status is not FindingStatus.CONFIRMED or not f.patch_diff:
            continue
        result = verifier(target, f.patch_diff, config, f.file, f.cls, f.evidence_sources)
        f.verification = result
        changed = True
        if result == "verified-static":
            f.status = FindingStatus.FIXED
            f.history.append({"event": "verify:fixed"})
            fixed += 1
    if changed:
        write_findings(ws, findings)
    return fixed


def main(argv: list[str] | None = None) -> int:
    """CLI: verify patches for a workspace's confirmed findings.

    Args:
        argv: Optional argument vector.

    Returns:
        0 on success.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-verify")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    n = verify_findings(Workspace(Path(args.workspace)), args.target, args.config)
    print(f"fixed {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
