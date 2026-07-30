"""Run SAST binaries and map their output to the common Finding model.

Only ``semgrep`` is wired in this plan; additional backends (opengrep, CodeQL,
SCA, secrets) attach behind the same ``list[Finding]`` return contract later.
"""

from __future__ import annotations

import json
import subprocess

from sec_harness.clsmap import cls_from_semgrep_meta
from sec_harness.models import Finding, FindingStatus, Severity

_SEMGREP_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def parse_semgrep_json(payload: dict) -> list[Finding]:
    """Map a semgrep ``--json`` payload to candidate findings.

    Args:
        payload: Parsed semgrep JSON output.

    Returns:
        One :class:`Finding` per semgrep result, ``status=CANDIDATE``.
    """
    findings: list[Finding] = []
    for i, r in enumerate(payload.get("results", []), start=1):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        check_id = r.get("check_id", "unknown")
        findings.append(
            Finding(
                id=f"C-{i:04d}",
                rule_id=check_id,
                cls=cls_from_semgrep_meta(meta, check_id),
                status=FindingStatus.CANDIDATE,
                severity=_SEMGREP_SEVERITY.get(extra.get("severity", "INFO"), Severity.LOW),
                file=r.get("path", ""),
                line=r.get("start", {}).get("line", 0),
                message=extra.get("message", ""),
                evidence=extra.get("lines", ""),
                evidence_sources=[f"semgrep:{check_id}"],
            )
        )
    return findings


def run_semgrep(target: str, config: str, *, runner=subprocess.run) -> list[Finding]:
    """Run semgrep against ``target`` with ``config`` and parse the results.

    Args:
        target: Path to scan.
        config: Path to a semgrep rules file.
        runner: Injectable subprocess runner (for testing).

    Returns:
        Candidate findings parsed from semgrep JSON output.
    """
    cmd = ["semgrep", "--config", config, "--json", "--no-git-ignore", target]
    completed = runner(cmd, capture_output=True, text=True, check=False)
    return parse_semgrep_json(json.loads(completed.stdout))
