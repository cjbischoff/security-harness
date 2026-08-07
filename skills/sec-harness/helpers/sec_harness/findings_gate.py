"""Deterministic gate: verify every finding file conforms to the schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sec_harness.campaign import record_stage
from sec_harness.evidence import is_tool_receipt
from sec_harness.models import Finding
from sec_harness.schema import validate as _schema_validate
from sec_harness.workspace import Workspace

_FINDING_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "references" / "finding.schema.json"


def _load_finding_schema() -> dict:
    """Load the finding JSON schema.

    Returns:
        The parsed ``finding.schema.json`` contents.
    """
    return json.loads(_FINDING_SCHEMA_PATH.read_text())


def validate_findings(ws: Workspace) -> list[str]:
    """Validate all finding files in a workspace.

    Each ``findings/*.json`` must parse as a :class:`Finding` and have a
    non-empty ``file``, ``line >= 1``, and a list ``dataflow``.

    Args:
        ws: Workspace to inspect.

    Returns:
        Error strings ``"<id-or-filename>: <problem>"``; empty if all valid.
    """
    errors: list[str] = []
    for p in sorted(ws.findings_dir.glob("*.json")):
        try:
            data = json.loads(p.read_text())
            f = Finding.from_dict(data)
        except (ValueError, TypeError, KeyError) as exc:
            errors.append(f"{p.stem}: unparseable finding ({exc})")
            continue
        errors.extend(f"{p.stem}: {e}" for e in _schema_validate(data, _load_finding_schema()))
        if not f.file:
            errors.append(f"{f.id}: empty file")
        if f.line < 1:
            errors.append(f"{f.id}: line must be >= 1")
        if not isinstance(f.dataflow, list):
            errors.append(f"{f.id}: dataflow must be a list")
        if f.status.value in ("raw", "confirmed") and f.duplicate_of is not None:
            errors.append(
                f"{f.id}: {f.status.value} finding must not set duplicate_of "
                f"(set status=duplicate instead)"
            )
        # Safety contract, now enforced (was prose-only): a confirmed/fixed finding
        # must rest on at least one mechanical tool receipt. LLM reasoning alone
        # (only ``llm-claimed:*`` sources) cannot suppress hallucination risk, so it
        # cannot carry a finding to confirmed. For SAST-unsupported languages a
        # ``ripgrep:`` receipt proving the sink exists is a valid mechanical ground.
        if f.status.value in ("confirmed", "fixed") and not any(
            is_tool_receipt(s) for s in f.evidence_sources
        ):
            errors.append(
                f"{f.id}: {f.status.value} finding has no mechanical tool receipt "
                f"(only {f.evidence_sources or 'no'} sources) — cannot confirm on "
                f"llm-claimed evidence alone; ground the sink with semgrep/codeql/"
                f"ast-grep/ripgrep"
            )
    record_stage(ws, "findings-gate")
    return errors


def main(argv: list[str] | None = None) -> int:
    """CLI: validate a workspace's findings and report errors.

    Args:
        argv: Optional argument vector.

    Returns:
        0 if all findings valid, 1 otherwise.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-findings-gate")
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args(argv)
    errors = validate_findings(Workspace(Path(args.workspace)))
    for e in errors:
        print(e)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
