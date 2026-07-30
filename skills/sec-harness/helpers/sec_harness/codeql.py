"""Run CodeQL and map its SARIF output onto the common Finding model.

CodeQL builds a semantic database from source (compiling the target for
compiled languages) and runs standard query suites (default: security-extended).
This module builds/analyzes a database and parses the resulting SARIF.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from sec_harness.clsmap import cls_from_cwe, cls_from_rule_id
from sec_harness.models import Finding, FindingStatus, Severity

_DANGEROUS = ("extractor", "buildcommand", "build-command", "setup",
              "pre-build", "post-build", "prebuild", "postbuild")


def codeql_config_trusted(target: str | Path) -> tuple[bool, str]:
    """Check a target's CodeQL config for dangerous fields before DB build.

    Since ``codeql database create`` builds/compiles the target on the host with
    no sandbox, an attacker-controlled CodeQL config (custom extractor, build
    hooks, external query refs) is an arbitrary-code-execution vector. Scan for
    those tokens and refuse unless the operator trusts the repo.

    Args:
        target: Repo root to inspect.

    Returns:
        ``(trusted, reason)``.
    """
    root = Path(target)
    candidates = [root / "qlpack.yml", root / "codeql-pack.yml", root / "codeql-config.yml"]
    gh = root / ".github" / "codeql"
    if gh.is_dir():
        candidates.extend(gh.glob("*.yml"))
        candidates.extend(gh.glob("*.yaml"))
    for path in candidates:
        if not path.is_file():
            continue
        text = path.read_text(errors="ignore").lower()
        for token in _DANGEROUS:
            if token in text:
                return False, f"dangerous CodeQL config field '{token}' in {path.name}"
        # external query pack refs outside codeql/ namespace
        for m in re.finditer(r"uses:\s*([^\s#]+)", text):
            ref = m.group(1).strip().strip("\"'")
            if ref.startswith((".", "/")) or (not ref.startswith("codeql/") and "/" in ref):
                return False, f"external query ref '{ref}' in {path.name}"
    return True, "no dangerous codeql config"


def qlpack_installed(language: str, *, packages_dir: Path | None = None) -> bool:
    """Return True if the CodeQL query pack for ``language`` is downloaded.

    ``codeql database analyze`` needs ``codeql/<language>-queries`` present in the
    local package cache (populated by ``codeql pack download``). The ``codeql``
    binary being on PATH does NOT imply the per-language packs exist — checking
    only the binary is a false green that silently drops all dataflow coverage
    for the language. This checks the cache directory that download populates.

    Args:
        language: CodeQL language id (``javascript``, ``python``, ...).
        packages_dir: Package cache root; defaults to ``~/.codeql/packages``.

    Returns:
        Whether ``<packages_dir>/codeql/<language>-queries`` exists.
    """
    base = packages_dir or (Path.home() / ".codeql" / "packages")
    return (base / "codeql" / f"{language}-queries").is_dir()


class CodeQLError(RuntimeError):
    """Raised when a CodeQL database build or analysis fails.

    Distinguishes a genuine backend failure (which must be surfaced, not
    swallowed as an empty result) from a successful scan that found nothing.
    """


def cls_from_tags(rule_id: str, tags: list[str]) -> str:
    """Map a CodeQL rule to an attack-class key via CWE tags, then rule id.

    CWE tags are the primary signal; but many ``security-extended`` rules carry
    no ``external/cwe`` tag (e.g. ``js/user-controlled-bypass``,
    ``js/insecure-randomness``) and would orphan to ``unknown``. When the CWE
    lookup fails, fall back to the rule-id router so those reach the right class
    instead of being dropped from class-based dispatch.

    Args:
        rule_id: The CodeQL rule id (e.g. ``js/user-controlled-bypass``).
        tags: Rule tags, which include ``external/cwe/cwe-089`` style entries.

    Returns:
        An attack-class key, or ``"unknown"`` if neither CWE nor rule id maps.
    """
    by_cwe = cls_from_cwe(tags)
    if by_cwe != "unknown":
        return by_cwe
    return cls_from_rule_id(rule_id) or "unknown"


def _severity_from_score(score: str | None, level: str) -> Severity:
    """Map CodeQL security-severity (CVSS-ish) or SARIF level to Severity."""
    if score is not None:
        try:
            s = float(score)
        except ValueError:
            s = 0.0
        if s >= 9.0:
            return Severity.CRITICAL
        if s >= 7.0:
            return Severity.HIGH
        if s >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW
    return {"error": Severity.HIGH, "warning": Severity.MEDIUM}.get(level, Severity.LOW)


def parse_codeql_sarif(payload: dict, *, source_root: str | None = None) -> list[Finding]:
    """Map a CodeQL SARIF document to candidate findings.

    Resolves uriBaseId references to construct repo-relative artifact paths. When a
    result's artifactLocation includes a uriBaseId and the run defines that base URI,
    the artifact path is prefixed with the base (stripped of ``file://`` scheme and
    surrounding slashes). Backward compatible: results without uriBaseId retain their
    original uri unchanged.

    Args:
        payload: Parsed CodeQL SARIF (2.1.0).
        source_root: Optional root path; reserved for future use. Does not affect
            current behavior when absent.

    Returns:
        One candidate :class:`Finding` per result.
    """
    findings: list[Finding] = []
    idx = 0
    for run in payload.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        base_map = {bid: info.get("uri", "") for bid, info in run.get("originalUriBaseIds", {}).items()}
        for r in run.get("results", []):
            idx += 1
            rule_id = r.get("ruleId", "unknown")
            props = rules.get(rule_id, {}).get("properties", {})
            tags = props.get("tags", [])
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact_loc = loc.get("artifactLocation", {})
            uri = artifact_loc.get("uri", "")
            base_id = artifact_loc.get("uriBaseId")

            # Resolve uriBaseId if present and defined in run's originalUriBaseIds
            if base_id and base_id in base_map:
                base = base_map[base_id]
                if base:
                    # Strip file:// scheme and leading/trailing slashes
                    base = base.replace("file://", "").strip("/")
                    if base:
                        uri = f"{base}/{uri}".strip("/")

            findings.append(
                Finding(
                    id=f"CQL-{idx:04d}",
                    rule_id=rule_id,
                    cls=cls_from_tags(rule_id, tags),
                    status=FindingStatus.CANDIDATE,
                    severity=_severity_from_score(props.get("security-severity"), r.get("level", "warning")),
                    file=uri,
                    line=loc.get("region", {}).get("startLine", 0),
                    message=r.get("message", {}).get("text", ""),
                    evidence_sources=[f"codeql:{rule_id}"],
                )
            )
    return findings


def run_codeql(
    target: str,
    language: str,
    db_dir: str,
    *,
    suite: str = "security-extended",
    runner=subprocess.run,
) -> list[Finding]:
    """Build a CodeQL DB for ``target`` and analyze it with ``suite``.

    Compiles the target (for compiled languages) into a semantic database, then
    runs the query suite and parses the SARIF. Requires the ``codeql`` CLI.

    Args:
        target: Source root to analyze.
        language: CodeQL language id (``go``, ``python``, ``javascript``, ...).
        db_dir: Directory to create the CodeQL database in.
        suite: Query suite (default ``security-extended``).
        runner: Injectable subprocess runner (for testing).

    Returns:
        Candidate findings parsed from the analysis SARIF.

    Raises:
        CodeQLError: If the database build or analysis fails, or no SARIF is
            produced. Failure is surfaced (with captured stderr) rather than
            returned as an empty finding list, so a broken scan is never
            mistaken for a clean one.
    """
    sarif_path = Path(db_dir).parent / "codeql.sarif"
    create = runner(
        ["codeql", "database", "create", db_dir, f"--language={language}", f"--source-root={target}", "--overwrite"],
        capture_output=True, text=True, check=False,
    )
    if create.returncode != 0:
        raise CodeQLError(
            f"codeql database create failed for language={language} "
            f"(exit {create.returncode}): {(create.stderr or '').strip()[-500:]}"
        )
    analyze = runner(
        ["codeql", "database", "analyze", db_dir, f"codeql/{language}-queries:codeql-suites/{language}-{suite}.qls",
         "--format=sarif-latest", f"--output={sarif_path}", "--rerun"],
        capture_output=True, text=True, check=False,
    )
    if analyze.returncode != 0:
        raise CodeQLError(
            f"codeql database analyze failed for language={language} "
            f"(exit {analyze.returncode}): {(analyze.stderr or '').strip()[-500:]}"
        )
    if not Path(sarif_path).exists():
        raise CodeQLError(
            f"codeql analyze produced no SARIF at {sarif_path} for language={language}"
        )
    return parse_codeql_sarif(json.loads(Path(sarif_path).read_text()))
