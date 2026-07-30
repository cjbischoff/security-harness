"""Workspace (KB) layout and per-finding JSON persistence."""

from __future__ import annotations

import json
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

    @property
    def kb(self) -> Path:
        """Knowledge-base directory (architecture, threat model, indexes)."""
        return self.kb_dir_override or self.root / "kb"

    @property
    def findings_dir(self) -> Path:
        """Directory holding one JSON file per finding."""
        return self.findings_dir_override or self.root / "findings"

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
        self._reports.mkdir(parents=True, exist_ok=True)


def write_findings(ws: Workspace, findings: list[Finding]) -> None:
    """Write each finding to ``findings/<id>.json``.

    Args:
        ws: Target workspace.
        findings: Findings to persist.
    """
    ws.findings_dir.mkdir(parents=True, exist_ok=True)
    for f in findings:
        (ws.findings_dir / f"{f.id}.json").write_text(json.dumps(f.to_dict(), indent=2))


def read_findings(ws: Workspace) -> list[Finding]:
    """Load all findings from the workspace, sorted by id.

    Args:
        ws: Source workspace.

    Returns:
        Findings sorted by id.
    """
    files = sorted(ws.findings_dir.glob("*.json"))
    return [Finding.from_dict(json.loads(p.read_text())) for p in files]


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
