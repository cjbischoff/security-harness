"""Software-composition analysis: run osv-scanner on the target's lockfiles.

SCA needs a vulnerability database, so — like semgrep/codeql — it delegates to an
external tool rather than reimplementing a CVE feed. ``osv-scanner`` is used when
present; when absent the caller records the backend as skipped (never a silent
no-op). The target is never executed.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from sec_harness.models import Finding, FindingStatus, Severity


class ScaError(RuntimeError):
    """Raised when the SCA tool runs but fails in a way that must be surfaced."""


_SEV = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _severity_from_vuln(vuln: dict) -> Severity:
    """Best-effort severity from an OSV vuln record's database_specific/severity."""
    ds = vuln.get("database_specific", {})
    sev = str(ds.get("severity", "")).upper()
    if sev in _SEV:
        return _SEV[sev]
    return Severity.MEDIUM


def parse_osv_json(payload: dict) -> list[Finding]:
    """Map an ``osv-scanner --format json`` document to candidate findings.

    Args:
        payload: Parsed osv-scanner JSON.

    Returns:
        One candidate :class:`Finding` per (package, vulnerability), ``cls="deps"``,
        each carrying an ``sca:osv`` mechanical receipt.
    """
    findings: list[Finding] = []
    idx = 0
    for result in payload.get("results", []):
        source = result.get("source", {}).get("path", "")
        for pkg in result.get("packages", []):
            info = pkg.get("package", {})
            name = info.get("name", "?")
            version = info.get("version", "?")
            for vuln in pkg.get("vulnerabilities", []):
                idx += 1
                vid = vuln.get("id", "OSV-UNKNOWN")
                summary = vuln.get("summary") or vuln.get("details", "")[:160] or vid
                findings.append(
                    Finding(
                        id=f"SCA-{idx:04d}",
                        rule_id=f"osv:{vid}",
                        cls="deps",
                        status=FindingStatus.CANDIDATE,
                        severity=_severity_from_vuln(vuln),
                        file=source,
                        line=1,
                        message=f"{name}@{version}: {vid} — {summary}",
                        evidence=f"{name}@{version}",
                        evidence_sources=[f"sca:osv:{vid}"],
                    )
                )
    return findings


def run_sca(target: str, *, runner=subprocess.run, has_tool=shutil.which) -> list[Finding]:
    """Run osv-scanner over ``target`` and parse its results.

    Args:
        target: Source root (scanned for lockfiles by osv-scanner; never executed).
        runner: Injectable subprocess runner.
        has_tool: Injectable binary-presence resolver.

    Returns:
        Candidate dependency findings.

    Raises:
        ScaError: If osv-scanner is absent (caller records it skipped) or errors
            in an unexpected way. osv-scanner exits non-zero (1) simply when it
            finds vulnerabilities — that is success, not an error.
    """
    if has_tool("osv-scanner") is None:
        raise ScaError("osv-scanner not installed")
    completed = runner(
        ["osv-scanner", "--format", "json", "--recursive", target],
        capture_output=True, text=True, check=False,
    )
    combined = (completed.stdout or "") + (completed.stderr or "")
    # "No package sources found" = ran fine, no manifests/lockfiles to scan (e.g.
    # lockfiles gitignored). That is a clean empty result, NOT an error.
    if "No package sources found" in combined:
        return []
    # exit 1 = vulns found (normal); empty stdout with a stderr = a real error.
    if not completed.stdout.strip():
        raise ScaError(f"osv-scanner produced no output (exit {completed.returncode}): "
                       f"{(completed.stderr or '').strip()[-300:]}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ScaError(f"osv-scanner output not JSON: {exc}") from None
    return parse_osv_json(payload)
