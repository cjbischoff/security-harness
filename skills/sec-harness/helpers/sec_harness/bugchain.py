"""Bug-chain analysis (Bucket B3, from dcrh other-use-cases).

Individually low/medium findings can compose into a critical (auth-bypass → IDOR → RCE). Humans
triaging one finding at a time miss this; a harness that sees the whole confirmed set can flag it.
This assembles the confirmed set and links findings that plausibly chain (share a file or a
dataflow node) so the bug-chain agent can reason about composed impact + re-prioritize. The
linking is a cheap deterministic prefilter; the agent decides whether a link is a real chain.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from sec_harness.models import Finding, FindingStatus

_REF = re.compile(r"[\w./-]+:\d+")
_CHAINABLE = {FindingStatus.CONFIRMED, FindingStatus.FIXED, FindingStatus.NEEDS_DEPLOYMENT_TESTING}


def _nodes(f: Finding) -> set[str]:
    """The file:line locations a finding touches (from its dataflow + its own site)."""
    nodes = {f"{f.file}:{f.line}"}
    for hop in f.dataflow:
        nodes.update(_REF.findall(hop))
    return nodes


def link_candidates(findings: list[Finding]) -> list[dict]:
    """Return plausible chain links between confirmed findings (empty if none).

    Two findings link if they share a file or a dataflow node — a cheap signal that one's
    output could be another's input. Each link: ``{"a", "b", "reason"}``. The agent adjudicates.
    """
    conf = [f for f in findings if f.status in _CHAINABLE]
    links: list[dict] = []
    for i, a in enumerate(conf):
        an = _nodes(a)
        for b in conf[i + 1:]:
            shared = an & _nodes(b)
            if shared:
                links.append({"a": a.id, "b": b.id, "reason": f"shared node(s): {sorted(shared)}"})
            elif a.file == b.file:
                links.append({"a": a.id, "b": b.id, "reason": f"same file: {a.file}"})
    return links


def assemble(findings: list[Finding]) -> dict:
    """Build the bug-chain agent's input: the chainable set + deterministic link prefilter."""
    conf = [f for f in findings if f.status in _CHAINABLE]
    return {
        "findings": [{"id": f.id, "cls": f.cls, "severity": f.severity.value,
                      "file": f.file, "line": f.line, "message": f.message,
                      "risk_score": f.risk_score} for f in conf],
        "links": link_candidates(findings),
    }


def main(argv: list[str] | None = None) -> int:
    """CLI: print the assembled bug-chain input (chainable set + link prefilter) for a workspace."""
    from sec_harness.workspace import Workspace, read_findings
    ap = argparse.ArgumentParser(prog="sec-harness-bugchain")
    ap.add_argument("--workspace", required=True)
    args = ap.parse_args(argv)
    print(json.dumps(assemble(read_findings(Workspace(Path(args.workspace)))), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
