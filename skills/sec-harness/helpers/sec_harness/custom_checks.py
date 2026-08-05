"""In-repo custom security-check bundle discovery.

A team encodes its own business-logic policy checks under a target repo's
``.sec-harness/checks/<check-id>/`` directory (checked in, versioned alongside the code
it describes). Each bundle is registered as an additional attack-class entry and
dispatched through the existing ``agents/investigate.md`` machinery — no separate,
lighter-weight validation path. This module only discovers and loads bundles; it does
not run them.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_CHECK_ID = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


@dataclass
class CustomCheck:
    """One discovered custom check bundle.

    ``applicable_paths``/``excluded_paths`` are read verbatim from the manifest and are
    not currently consumed by anything in this module or ``SKILL.md``'s orchestration —
    no code scopes investigation to/away from these paths yet. They are untrusted,
    manifest-supplied strings (same threat model as ``instructionsFile``/``semgrepRule``):
    a future consumer that turns them into filesystem globs or semgrep ``--include``
    arguments MUST route them through a containment check like ``_resolve_within``
    first, not use them as raw path fragments.
    """

    check_id: str
    name: str
    severity: str
    instructions_path: Path
    semgrep_rule_path: Path | None = None
    applicable_paths: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)


def _resolve_within(bundle_dir: Path, filename: str) -> Path | None:
    """Resolve ``filename`` against ``bundle_dir``, rejecting any escape.

    A manifest's file references come from the target repo — untrusted content per
    this harness's threat model — so an absolute path or a ``../`` traversal must not
    be allowed to resolve outside the bundle directory.

    Args:
        bundle_dir: The check bundle's own directory.
        filename: The manifest-specified filename (``instructionsFile``/``semgrepRule``).

    Returns:
        The resolved path if it stays within ``bundle_dir``, else ``None``.
    """
    resolved_bundle_dir = bundle_dir.resolve()
    candidate = (bundle_dir / filename).resolve()
    if candidate != resolved_bundle_dir and resolved_bundle_dir not in candidate.parents:
        return None
    return bundle_dir / filename


def _validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []
    for key in ("name", "severity", "instructionsFile"):
        if not manifest.get(key):
            errors.append(f"missing required field {key!r}")
    if manifest.get("severity") is not None and manifest["severity"] not in _VALID_SEVERITIES:
        errors.append(f"severity must be one of {sorted(_VALID_SEVERITIES)}")
    return errors


def discover_custom_checks(target_root: str | Path) -> list[CustomCheck]:
    """Scan ``.sec-harness/checks/`` under ``target_root`` for custom check bundles.

    A malformed bundle (missing/invalid manifest, missing required field, invalid
    severity, missing instructions file) is skipped with a warning printed to stderr —
    it never raises, so one broken bundle cannot stop discovery of the rest.

    Args:
        target_root: The target repo's root directory.

    Returns:
        Discovered bundles, sorted by ``check_id``. Empty list if no checks directory
        exists.
    """
    checks_dir = Path(target_root) / ".sec-harness" / "checks"
    if not checks_dir.is_dir():
        return []

    out: list[CustomCheck] = []
    for bundle_dir in sorted(p for p in checks_dir.iterdir() if p.is_dir()):
        check_id = bundle_dir.name
        if not _VALID_CHECK_ID.match(check_id):
            print(
                f"custom_checks: skipping bundle with unsafe check_id {check_id!r} "
                f"(must match {_VALID_CHECK_ID.pattern!r})",
                file=sys.stderr,
            )
            continue
        manifest_path = bundle_dir / f"{check_id}.json"
        if not manifest_path.is_file():
            print(f"custom_checks: skipping {check_id}: missing {manifest_path.name}", file=sys.stderr)
            continue
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"custom_checks: skipping {check_id}: invalid JSON ({exc})", file=sys.stderr)
            continue

        errors = _validate_manifest(manifest)
        if errors:
            print(f"custom_checks: skipping {check_id}: {'; '.join(errors)}", file=sys.stderr)
            continue

        instructions_path = _resolve_within(bundle_dir, manifest["instructionsFile"])
        if instructions_path is None:
            print(
                f"custom_checks: skipping {check_id}: instructionsFile "
                f"{manifest['instructionsFile']!r} escapes the bundle directory",
                file=sys.stderr,
            )
            continue
        if not instructions_path.is_file():
            print(
                f"custom_checks: skipping {check_id}: instructions file "
                f"{manifest['instructionsFile']} not found",
                file=sys.stderr,
            )
            continue

        semgrep_rule_path = None
        if manifest.get("semgrepRule"):
            candidate = _resolve_within(bundle_dir, manifest["semgrepRule"])
            if candidate is None:
                print(
                    f"custom_checks: {check_id}: semgrepRule {manifest['semgrepRule']!r} "
                    "escapes the bundle directory, ignoring",
                    file=sys.stderr,
                )
            elif candidate.is_file():
                semgrep_rule_path = candidate
            else:
                print(
                    f"custom_checks: {check_id}: semgrepRule {manifest['semgrepRule']} "
                    "not found, ignoring",
                    file=sys.stderr,
                )

        out.append(
            CustomCheck(
                check_id=check_id,
                name=manifest["name"],
                severity=manifest["severity"],
                instructions_path=instructions_path,
                semgrep_rule_path=semgrep_rule_path,
                applicable_paths=list(manifest.get("applicablePaths", [])),
                excluded_paths=list(manifest.get("excludedPaths", [])),
            )
        )
    return out


def custom_check_classes(checks: list[CustomCheck]) -> list[str]:
    """Return the attack-class keys (``check_id``s) for a list of discovered checks."""
    return [c.check_id for c in checks]


def merge_custom_check_classes(agents_to_spawn: list[str], checks: list[CustomCheck]) -> list[str]:
    """Append custom-check classes not already in ``agents_to_spawn``.

    Args:
        agents_to_spawn: The profile's planned attack-class list.
        checks: Discovered custom checks (see :func:`discover_custom_checks`).

    Returns:
        ``agents_to_spawn`` followed by any custom-check ids not already present.
        Never removes or reorders a planned class.
    """
    existing = set(agents_to_spawn)
    extra = [c.check_id for c in checks if c.check_id not in existing]
    return list(agents_to_spawn) + extra


def custom_check_instructions(check: CustomCheck) -> str:
    """Read a custom check's instructions file content."""
    return check.instructions_path.read_text()
