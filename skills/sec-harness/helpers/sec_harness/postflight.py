"""Postflight: distill a finished scan into durable cross-scan context (Phase C2).

Preflight context is volatile (regenerated each scan); postflight is what STICKS. It
writes ``kb/prior_context.json`` (accretes across scans, drift-keyed by SHA) that the
NEXT scan's context-ingest reads as higher-trust prior context: confirmed findings,
rejected-with-rationale (so we don't re-litigate settled non-findings), and a short
codebase security profile. Our own conclusions are higher-trust than repo docs, but
still re-validated on drift (changed files re-open; unchanged files persist).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sec_harness.campaign import record_stage
from sec_harness.context import Context, ContextItem, prior_context_path
from sec_harness.models import Finding, FindingStatus
from sec_harness.workspace import Workspace, read_findings


def _rejection_rationale(f: Finding) -> str:
    """Best rationale for a rejected finding, from its history events."""
    for h in reversed(f.history):
        ev = str(h.get("event", ""))
        if "reject" in ev:
            return h.get("reason") or ev
    return (f.message or "rejected")[:160]


def build_prior_context(ws: Workspace, sha: str | None) -> Context:
    """Build the durable prior-context from a workspace's settled findings.

    Args:
        ws: The finished scan's workspace.
        sha: The scanned SHA (stamped into provenance + each item's ``where`` note).

    Returns:
        A :class:`sec_harness.context.Context` of ``prior-scan``-trust items.
    """
    items: list[ContextItem] = []
    for f in read_findings(ws):
        fp = f.fingerprint or f"{f.file}:{f.line}:{f.cls}"
        if f.status in (FindingStatus.CONFIRMED, FindingStatus.FIXED):
            items.append(ContextItem(
                kind="prior_finding", trust="prior-scan", cls=f.cls,
                text=f"{f.status.value} {f.cls}: {(f.message or '')[:120]} [fp:{fp}]",
                where=f"{f.file}:{f.line}", source_doc=f"scan@{sha}"))
        elif f.status is FindingStatus.REJECTED:
            items.append(ContextItem(
                kind="note", trust="prior-scan", cls=f.cls,
                text=f"settled non-finding ({f.cls}): {_rejection_rationale(f)} "
                     f"— do not re-litigate unless this file changed [fp:{fp}]",
                where=f"{f.file}:{f.line}", source_doc=f"scan@{sha}"))
    return Context(items=items, provenance={"sha": sha, "kind": "postflight"})


def _merge(old: Context, new: Context, changed_files: set[str]) -> Context:
    """Merge new postflight over old prior-context, drift-aware.

    Old items whose file is in ``changed_files`` are dropped (re-opened this pass); the
    rest are kept. New items are appended (deduped by (kind, where, text-prefix)).
    """
    def key(i: ContextItem):
        return (i.kind, i.where, i.text[:60])
    kept = [i for i in old.items if i.where.split(":", 1)[0] not in changed_files]
    seen = {key(i) for i in kept}
    for i in new.items:
        if key(i) not in seen:
            kept.append(i)
            seen.add(key(i))
    return Context(items=kept, provenance=new.provenance)


def run_postflight(ws: Workspace, sha: str | None, *, changed_files: set[str] | None = None) -> int:
    """Distill the scan and merge into the durable prior_context.json.

    Args:
        ws: Finished scan workspace.
        sha: Scanned SHA.
        changed_files: Repo-relative files changed since the last postflight (drift);
            old conclusions on these are dropped so the next scan re-examines them.

    Returns:
        Total item count in the merged prior context.
    """
    new = build_prior_context(ws, sha)
    p = prior_context_path(ws)
    old = Context.from_dict(json.loads(p.read_text())) if p.exists() else Context()
    merged = _merge(old, new, changed_files or set())
    ws.kb.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(merged.to_dict(), indent=2))
    record_stage(ws, "postflight")
    return len(merged.items)


def main(argv: list[str] | None = None) -> int:
    """CLI: run postflight distillation for a workspace."""
    ap = argparse.ArgumentParser(prog="sec-harness-postflight")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--sha", default=None)
    args = ap.parse_args(argv)
    n = run_postflight(Workspace(Path(args.workspace)), args.sha)
    print(f"prior_context.json now holds {n} item(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
