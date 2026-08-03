"""Workspace (KB) layout and per-finding JSON persistence."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sec_harness.models import Finding


@dataclass
class Workspace:
    """Filesystem layout for a campaign's knowledge base and outputs.

    Attributes:
        root: The ``workspace/`` directory root.
        reports_dir: Override for report paths (sarif_path, report_path, findings_json_path).
        findings_dir_override: Override for findings_dir.
        kb_dir_override: Override for kb directory.
    """

    root: Path
    reports_dir: Path | None = None
    findings_dir_override: Path | None = None
    kb_dir_override: Path | None = None

    def __post_init__(self) -> None:
        """Coerce str paths to Path so agent-authored ``Workspace('<path>')`` works."""
        self.root = Path(self.root)
        for attr in ("reports_dir", "findings_dir_override", "kb_dir_override"):
            value = getattr(self, attr)
            if value is not None:
                setattr(self, attr, Path(value))

    @property
    def kb(self) -> Path:
        """Knowledge-base directory (architecture, threat model, indexes)."""
        return self.kb_dir_override or self.root / "kb"

    @property
    def findings_dir(self) -> Path:
        """Directory holding one JSON file per finding."""
        return self.findings_dir_override or self.root / "findings"

    @property
    def runs(self) -> Path:
        """Directory holding each agent's persisted final return (``<agent>.txt``)."""
        return self.root / "runs"

    @property
    def reports(self) -> Path:
        """Reports directory (holds report.sarif / report.md / findings.json)."""
        return self.reports_dir or self.root

    @property
    def _reports(self) -> Path:
        """Deprecated internal alias for :pyattr:`reports`."""
        return self.reports

    @property
    def state_path(self) -> Path:
        """Path to the campaign state file."""
        return self.root / "state.json"

    @property
    def sarif_path(self) -> Path:
        """Path to the emitted SARIF report."""
        return self._reports / "report.sarif"

    @property
    def report_path(self) -> Path:
        """Path to the emitted Markdown report."""
        return self._reports / "report.md"

    @property
    def findings_json_path(self) -> Path:
        """Path to the emitted findings JSON file."""
        return self._reports / "findings.json"

    def ensure(self) -> None:
        """Create the workspace directory tree if absent."""
        self.kb.mkdir(parents=True, exist_ok=True)
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.runs.mkdir(parents=True, exist_ok=True)
        self._reports.mkdir(parents=True, exist_ok=True)


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (temp file in the same dir + ``os.replace``).

    Args:
        path: Destination file.
        text: Content to write.

    Note:
        The temp file shares ``path``'s directory so ``os.replace`` is a same-filesystem
        rename (atomic on POSIX/Windows). A crash before the rename leaves ``path``
        untouched; a stray temp file is removed on the failure path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_findings(ws: Workspace, findings: list[Finding]) -> None:
    """Write each finding to ``findings/<id>.json`` atomically.

    Serializes each finding fully before touching disk so a serialization error never
    truncates an existing file. Each write is a temp-file + ``os.replace`` (see
    :func:`_atomic_write`), safe against a concurrent reader in another phase.

    Args:
        ws: Target workspace.
        findings: Findings to persist.
    """
    ws.findings_dir.mkdir(parents=True, exist_ok=True)
    for f in findings:
        payload = json.dumps(f.to_dict(), indent=2)
        _atomic_write(ws.findings_dir / f"{f.id}.json", payload)


def record_agent_return(ws: Workspace, agent: str, text: str) -> None:
    """Persist an agent's final return to ``runs/<agent>.txt`` (T13).

    Lets the orchestrator rely on durable disk state instead of a subagent's summary
    message, which does not always propagate back.

    Args:
        ws: Target workspace.
        agent: Agent/phase label (used as the filename stem).
        text: The agent's final return text.
    """
    _atomic_write(ws.runs / f"{agent}.txt", text)


def read_agent_return(ws: Workspace, agent: str) -> str | None:
    """Read a persisted agent return, or ``None`` if none was recorded.

    Args:
        ws: Source workspace.
        agent: Agent/phase label.

    Returns:
        The recorded text, or ``None`` when ``runs/<agent>.txt`` is absent.
    """
    p = ws.runs / f"{agent}.txt"
    return p.read_text() if p.is_file() else None


def read_findings(ws: Workspace) -> list[Finding]:
    """Load all parseable findings from the workspace, sorted by id.

    A single malformed finding file (e.g. an agent-emitted out-of-enum value) is
    skipped with a warning to stderr rather than raising — one bad file must not
    halt every downstream phase (dogfood ISSUE-015). ``findings_gate`` remains the
    authority that fails the pass on any unparseable finding.

    Args:
        ws: Source workspace.

    Returns:
        The parseable findings, sorted by id.
    """
    findings: list[Finding] = []
    for p in sorted(ws.findings_dir.glob("*.json")):
        try:
            findings.append(Finding.from_dict(json.loads(p.read_text())))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            print(f"warning: skipping unparseable finding {p.name}: {exc}", file=sys.stderr)
    return findings


def load_paths(
    *,
    workspace: str | Path | None,
    paths_config: str | Path | None = None,
    reports_dir: str | Path | None = None,
    findings_dir: str | Path | None = None,
    kb_dir: str | Path | None = None,
) -> Workspace:
    """Resolve a Workspace from flags + optional paths.json (flag > config > derive).

    Precedence for each path: explicit flag > paths.json value > None (derive at use-time).
    An explicit ``workspace`` arg always overrides the config's ``workspace``.

    Args:
        workspace: Workspace root directory (required).
        paths_config: Path to optional paths.json config file.
        reports_dir: Override for report output directory.
        findings_dir: Override for findings directory (maps to findings_dir_override).
        kb_dir: Override for KB directory (maps to kb_dir_override).

    Returns:
        Configured Workspace instance.

    Raises:
        ValueError: If no workspace path is resolvable.
    """
    cfg: dict = {}
    if paths_config is not None:
        cfg = json.loads(Path(paths_config).read_text())

    def pick(flag: str | Path | None, key: str) -> Path | None:
        """Pick from flag, config, or None (derive)."""
        v = flag if flag is not None else cfg.get(key)
        return Path(v) if v is not None else None

    root = pick(workspace, "workspace")
    if root is None:
        raise ValueError("workspace path is required (flag or paths.json)")

    return Workspace(
        root,
        reports_dir=pick(reports_dir, "reports_dir"),
        findings_dir_override=pick(findings_dir, "findings_dir"),
        kb_dir_override=pick(kb_dir, "kb_dir"),
    )
