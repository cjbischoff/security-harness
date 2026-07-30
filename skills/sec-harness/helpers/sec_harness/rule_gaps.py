"""Rule-gap feedback: confirmed findings no detection rule would have caught.

When a finding reaches ``confirmed`` grounded only by agent hunting (threat-model /
investigate reasoning) rather than a detection rule (semgrep/codeql/rule-matcher), it
is evidence the rule corpus has a blind spot. Recording these feeds rule/clsmap
authoring — the harness learns which real bugs its deterministic layer misses.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sec_harness.models import Finding, FindingStatus
from sec_harness.workspace import Workspace, read_findings

# Sources that mean "a detection RULE surfaced this" (vs agent navigation/claims).
_RULE_ORIGINS = ("semgrep:", "codeql:", "sca:", "secrets:", "asvs:", "codeguard:")


def is_rule_originated(f: Finding) -> bool:
    """True if a detection rule (not just agent navigation) surfaced this finding.

    ``ripgrep:``/``ast-grep:``/``structural-index:`` are navigation/grounding aids, not
    detectors — a finding backed only by those + ``llm-claimed`` was found by hunting.
    """
    return any(s.startswith(_RULE_ORIGINS) for s in f.evidence_sources)


def gaps_path(ws: Workspace) -> Path:
    """Path to the append-only rule-gaps log."""
    return ws.kb / "rule_gaps.jsonl"


def record_rule_gaps(ws: Workspace, *, ts: str | None = None) -> int:
    """Record confirmed, non-rule-originated findings as rule gaps (dedup by fingerprint).

    Args:
        ws: Workspace to scan + write into.
        ts: Optional timestamp string stamped on new entries.

    Returns:
        The number of NEW gaps recorded this call.
    """
    path = gaps_path(ws)
    seen = set()
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                seen.add(json.loads(line).get("fingerprint"))
    new = 0
    with path.open("a") as fh:
        for f in read_findings(ws):
            if f.status is not FindingStatus.CONFIRMED or is_rule_originated(f):
                continue
            fp = f.fingerprint or f"{f.file}:{f.line}:{f.cls}"
            if fp in seen:
                continue
            seen.add(fp)
            fh.write(json.dumps({
                "fingerprint": fp, "cls": f.cls, "file": f.file, "line": f.line,
                "why_missed": "confirmed via hunting; no detection rule matched",
                "evidence_sources": f.evidence_sources, "ts": ts,
            }) + "\n")
            new += 1
    return new


def load_rule_gaps(ws: Workspace) -> list[dict]:
    """Load recorded rule gaps."""
    path = gaps_path(ws)
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


_EXT_LANG = {".py": "python", ".js": "javascript", ".ts": "typescript", ".go": "go",
             ".java": "java", ".rb": "ruby", ".php": "php", ".c": "c", ".cpp": "cpp"}


def emit_semgrep_rule(f: Finding) -> dict | None:
    """Draft a minimal semgrep rule from a confirmed finding (Bucket B5), or ``None``.

    dcrh's lesson: codify each recognizable finding as a rule — a cheap deterministic FLOOR that
    both sweeps siblings and becomes a mechanical receipt on the next run. This drafts a
    single-pattern rule from the finding's evidence line; it is a starting point for a human to
    tighten, not a finished detector. Returns ``None`` when there is no usable evidence/language.
    """
    ext = f.file[f.file.rfind("."):] if "." in f.file else ""
    lang = _EXT_LANG.get(ext)
    pattern = (f.evidence or "").strip().split("\n", 1)[0]
    if not lang or not pattern:
        return None
    fp = (f.fingerprint or f"{f.file}:{f.line}:{f.cls}").replace(":", "_").replace("/", "_")
    return {"rules": [{
        "id": f"sec-harness.{f.cls}.{fp}",
        "message": f.message or f"{f.cls} (codified from confirmed finding {f.id})",
        "severity": "ERROR" if f.severity.value in ("critical", "high") else "WARNING",
        "languages": [lang],
        "metadata": {"cls": f.cls, "source": "sec-harness:codified", "origin_finding": f.id},
        "patterns": [{"pattern": pattern}],
    }]}


def main(argv: list[str] | None = None) -> int:
    """CLI: record and/or report rule gaps for a workspace."""
    p = argparse.ArgumentParser(prog="sec-harness-rule-gaps")
    p.add_argument("--workspace", required=True)
    p.add_argument("--report", action="store_true")
    args = p.parse_args(argv)
    ws = Workspace(Path(args.workspace))
    n = record_rule_gaps(ws)
    print(f"recorded {n} new rule gap(s)")
    if args.report:
        for g in load_rule_gaps(ws):
            print(f"  [{g['cls']}] {g['file']}:{g['line']} — {g['why_missed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
