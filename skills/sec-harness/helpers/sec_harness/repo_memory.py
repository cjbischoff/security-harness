"""Per-repo persistent scan memory.

Every scanned repo gets a durable memory folder that OUTLIVES a single run. By
default it lives INSIDE the reviewed codebase at ``<target>/.sec-harness/<slug>/``
(override the base with ``$SEC_HARNESS_HOME`` for an external location, or the whole
workspace with ``--workspace``). The harness never executes or modifies the reviewed
SOURCE — its own artifacts live in this self-ignoring ``.sec-harness/`` sidecar dir,
which is git-ignored so scan output never pollutes the repo's tree. The folder holds:

- the campaign ``Workspace`` (``kb/`` — recon/architecture/THREAT_MODEL; ``findings/``;
  ``state.json``) so passes resume across invocations;
- ``MEMORY.md`` — a human-readable index (identity, current status, learnings log);
- ``learnings/<date>.md`` — dated free-text learnings accumulated across runs;
- ``runs/`` — optional per-run report snapshots.

``run_status()`` reads the campaign state to answer "did this finish, and if not where
does it resume" so an interrupted scan continues instead of restarting.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import date as _date
from pathlib import Path

from sec_harness.workspace import Workspace

# Canonical phase order — a repo's scan is "finished" for a SHA once "report" is
# recorded; resume picks the first phase not yet recorded.
PHASES: tuple[str, ...] = (
    "recon", "architecture", "threat_model", "prefilter", "investigate",
    "dedupe", "critic", "validate", "calibrate", "patch", "verify", "report",
)

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def memory_root(target: str | Path | None = None) -> Path:
    """Return the base directory holding a repo's ``<slug>`` memory folder.

    Resolution precedence:
        1. ``$SEC_HARNESS_HOME`` if set — an explicit external base.
        2. ``<target>/.sec-harness`` when ``target`` is given — the default, an
           in-repo sidecar next to the reviewed code.
        3. ``~/.sec-harness`` as a last resort when no target is known.

    Args:
        target: Path to the reviewed repo. When given (and no env override), the
            base is the in-repo ``.sec-harness`` sidecar.

    Returns:
        The base directory that will hold ``<slug>/``.
    """
    env = os.environ.get("SEC_HARNESS_HOME")
    if env:
        return Path(env).expanduser()
    if target is not None:
        return Path(target).expanduser().resolve() / ".sec-harness"
    return Path.home() / ".sec-harness"


def repo_slug(target: str | Path, *, runner=subprocess.run) -> str:
    """Derive a stable, filesystem-safe slug identifying a scan target.

    Prefers the git ``origin`` remote URL (stable across clone locations); falls back to the
    absolute path. For a monorepo sub-service the identity also includes the target's path
    relative to the git top-level, so two sub-services of one repo never collide. A short
    hash of the identity is appended.

    Args:
        target: Path to the scan target.
        runner: Injectable subprocess runner (for testing).

    Returns:
        A slug like ``svca-1a2b3c4d`` (monorepo sub-service) or ``myrepo-1a2b3c4d``.
    """
    target = Path(target)
    identity = str(target.resolve())
    name = target.name
    try:
        res = runner(["git", "-C", str(target), "remote", "get-url", "origin"],
                     capture_output=True, text=True, check=False)
        url = (res.stdout or "").strip()
        if res.returncode == 0 and url:
            top = runner(["git", "-C", str(target), "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=False)
            toplevel = (top.stdout or "").strip()
            subpath = ""
            if top.returncode == 0 and toplevel:
                try:
                    subpath = target.resolve().relative_to(Path(toplevel).resolve()).as_posix()
                except ValueError:
                    subpath = ""
            identity = url + ("#" + subpath if subpath and subpath != "." else "")
            base_src = subpath.rsplit("/", 1)[-1] if subpath and subpath != "." else \
                re.sub(r"\.git$", "", url.rstrip("/").rsplit("/", 1)[-1])
            name = base_src or name
    except OSError:
        pass
    base = _SLUG_RE.sub("-", name.lower()).strip("-") or "repo"
    digest = hashlib.sha256(identity.encode()).hexdigest()[:8]
    return f"{base}-{digest}"


@dataclass
class RepoMemory:
    """Durable per-repo memory folder + the campaign workspace inside it."""

    root: Path

    @classmethod
    def for_target(cls, target: str | Path, *, base: Path | None = None,
                   runner=subprocess.run) -> RepoMemory:
        """Resolve (do not create) the memory folder for a target repo.

        Args:
            target: Path to the target repo.
            base: Override for the memory base dir (default :func:`memory_root`).
            runner: Injectable subprocess runner.

        Returns:
            A :class:`RepoMemory` for ``<base>/<slug>``.
        """
        b = base or memory_root(target)
        return cls(root=b / repo_slug(target, runner=runner))

    @property
    def workspace(self) -> Workspace:
        """The campaign Workspace rooted in this memory folder (KB/findings/state)."""
        return Workspace(self.root)

    @property
    def index_path(self) -> Path:
        """Path to ``MEMORY.md``, the human-readable index."""
        return self.root / "MEMORY.md"

    @property
    def learnings_dir(self) -> Path:
        """Directory of dated learnings files."""
        return self.root / "learnings"

    def ensure(self, target: str | Path | None = None) -> None:
        """Create the memory tree and seed ``MEMORY.md`` if absent.

        Args:
            target: Optional target path, recorded in the index header on first create.
        """
        self.workspace.ensure()
        self.learnings_dir.mkdir(parents=True, exist_ok=True)
        (self.root / "runs").mkdir(parents=True, exist_ok=True)
        # Make the .sec-harness sidecar self-ignoring so in-repo scan output never
        # pollutes the reviewed repo's git tree. Only seeded if absent — never clobbers
        # an existing one. root is <base>/<slug>; the sidecar base is root.parent.
        sidecar_ignore = self.root.parent / ".gitignore"
        if not sidecar_ignore.exists():
            sidecar_ignore.parent.mkdir(parents=True, exist_ok=True)
            sidecar_ignore.write_text("# sec-harness scan artifacts — not source\n*\n")
        if not self.index_path.exists():
            hdr = [
                f"# sec-harness memory — {self.root.name}",
                "",
                f"- Target: `{target}`" if target else "- Target: (unspecified)",
                "- Purpose: durable per-repo scan memory (KB, findings, dated learnings, resume state).",
                "",
                "## Status",
                "",
                "_No completed run recorded yet._",
                "",
                "## Learnings log",
                "",
            ]
            self.index_path.write_text("\n".join(hdr) + "\n")

    def run_status(self) -> dict:
        """Report whether the current pass finished and where it resumes.

        Returns:
            ``{exists, active_sha, pass_number, stages_done, finished, resumable,
            next_phase}``. ``finished`` is True when ``report`` is recorded for the
            active SHA; ``next_phase`` is the first PHASE not yet recorded (None if
            finished or no state).
        """
        sp = self.workspace.state_path
        if not sp.exists():
            return {"exists": False, "active_sha": None, "pass_number": 0,
                    "stages_done": [], "finished": False, "resumable": False,
                    "next_phase": PHASES[0]}
        state = json.loads(sp.read_text())
        stages = state.get("stages", {})
        done = [p for p in PHASES if p in stages]
        finished = "report" in stages
        remaining = [p for p in PHASES if p not in stages]
        next_phase = None if finished or not remaining else remaining[0]
        return {
            "exists": True,
            "active_sha": state.get("active_sha"),
            "pass_number": state.get("pass_number", 1),
            "stages_done": done,
            "finished": finished,
            "resumable": bool(done) and not finished,
            "next_phase": next_phase,
        }

    def record_learning(self, text: str, *, today: _date | None = None,
                         tag: str = "") -> Path:
        """Append a dated learning and index it in ``MEMORY.md``.

        Args:
            text: The learning (markdown).
            today: Injectable date (defaults to today).
            tag: Optional short tag shown in the index line.

        Returns:
            Path to the dated learnings file written.
        """
        self.ensure()
        d = (today or _date.today()).isoformat()  # noqa: DTZ011 — a calendar date; injectable
        path = self.learnings_dir / f"{d}.md"
        entry = f"\n- {text.strip()}\n"
        with path.open("a") as f:
            if not path.stat().st_size:
                f.write(f"# Learnings — {d}\n")
            f.write(entry)
        # index pointer in MEMORY.md
        pointer = f"- {d}{(' [' + tag + ']') if tag else ''}: {text.strip().splitlines()[0][:120]}"
        idx = self.index_path.read_text()
        idx = idx.rstrip() + "\n" + pointer + "\n"
        self.index_path.write_text(idx)
        return path

    def update_status(self) -> None:
        """Rewrite the ``## Status`` block of ``MEMORY.md`` from current run state."""
        self.ensure()
        st = self.run_status()
        if not st["exists"]:
            block = "_No completed run recorded yet._"
        else:
            state = "FINISHED" if st["finished"] else (
                f"IN PROGRESS (resume at `{st['next_phase']}`)" if st["resumable"]
                else "STARTED")
            block = (
                f"- Pass: {st['pass_number']} @ `{st['active_sha']}`\n"
                f"- State: **{state}**\n"
                f"- Stages done: {', '.join(st['stages_done']) or '(none)'}"
            )
        text = self.index_path.read_text()
        # replace everything between "## Status" and the next "## " heading
        new = re.sub(
            r"(## Status\n\n).*?(\n## )",
            lambda m: m.group(1) + block + m.group(2),
            text, count=1, flags=re.DOTALL,
        )
        self.index_path.write_text(new if new != text else text)
