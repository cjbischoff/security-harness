"""Red-team phase — the static->runtime bridge.

Static analysis proves some findings outright and leaves others high-confidence-but-not-
provable-from-source: exploitability gated on runtime state (auth/session bypass reachability,
TOCTOU/races, real payload delivery, business-logic abuse). This module discriminates confirmed
findings into ``static-settled`` vs ``needs-runtime`` and renders a prioritized MANUAL runtime
test plan a human executes against the running system. The harness never executes the target —
this emits a plan only.

Signal over noise: only findings at or above a confidence bar (``risk_score``) enter the plan;
weaker runtime candidates are logged as gaps, not handed to an operator as action items.
"""

from __future__ import annotations

import argparse
import json

from sec_harness.evidence import is_tool_receipt
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, load_paths, read_findings

DEFAULT_MIN_RISK = 7
_REPORTABLE = {FindingStatus.CONFIRMED, FindingStatus.FIXED}
_ACTIONABLE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def wants_runtime(f: Finding) -> bool:
    """True if a finding's exploitability can only be settled by testing the running system."""
    return f.runtime_disposition == "needs-runtime" or f.status is FindingStatus.NEEDS_DEPLOYMENT_TESTING


def _above_bar(f: Finding, min_risk: int) -> bool:
    """A needs-runtime finding is actionable if its severity is >= medium, else gated by min_risk.

    Fixes O-016/O-031: min_risk can no longer hide a confirmed critical/high whose deterministic
    risk_score sits low.
    """
    if f.severity in _ACTIONABLE_SEVERITIES:
        return True
    return (f.risk_score or 0) >= min_risk


def discriminate(findings: list[Finding], min_risk: int = DEFAULT_MIN_RISK) -> dict:
    """Partition findings for the runtime plan.

    Considers confirmed/fixed findings plus ``needs-deployment-testing`` leads. A runtime
    candidate reaches the plan only if its ``risk_score`` meets ``min_risk`` (signal over noise).

    Args:
        findings: All workspace findings.
        min_risk: Confidence/priority bar (1-10) a runtime candidate must meet to enter the plan.

    Returns:
        ``{"needs_runtime": [...], "static_settled": [...], "below_bar": [...]}`` — each a list
        of :class:`Finding`, sorted by descending risk then id.
    """
    plan: list[Finding] = []
    static_settled: list[Finding] = []
    below_bar: list[Finding] = []
    for f in findings:
        is_reportable = f.status in _REPORTABLE
        is_ndt = f.status is FindingStatus.NEEDS_DEPLOYMENT_TESTING
        if not (is_reportable or is_ndt):
            continue
        if wants_runtime(f):
            (plan if _above_bar(f, min_risk) else below_bar).append(f)
        else:
            static_settled.append(f)

    def key(f: Finding):
        return (-(f.risk_score or 0), f.id)

    return {
        "needs_runtime": sorted(plan, key=key),
        "static_settled": sorted(static_settled, key=key),
        "below_bar": sorted(below_bar, key=key),
    }


def _directive_block(f: Finding) -> str:
    """Render one manual runtime-test directive from a finding's ``runtime_test`` block."""
    rt = f.runtime_test or {}
    receipts = [s for s in f.evidence_sources if is_tool_receipt(s)]
    payloads = rt.get("payloads") or []
    payload_md = "\n".join(f"  - `{p}`" for p in payloads) if payloads else "  - _(none supplied)_"
    return "\n".join([
        f"### {f.id} — {f.cls} — risk {f.risk_score if f.risk_score is not None else '-'}",
        "",
        f"- **Objective:** {rt.get('objective', f.message)}",
        f"- **Preconditions / access:** {rt.get('preconditions', '_not specified_')}",
        "- **Payload(s)** (shell vars only — export before use):",
        payload_md,
        f"- **Expected signal:** {rt.get('expected_signal', '_not specified_')}",
        f"- **Telemetry to watch:** {rt.get('telemetry', '_not specified_')}",
        f"- **Static evidence:** `{f.file}:{f.line}` — "
        + (", ".join(f"`{r}`" for r in receipts) or "_no tool receipt (verify carefully)_"),
        "",
    ])


def render_plan(disc: dict, min_risk: int = DEFAULT_MIN_RISK) -> str:
    """Render the manual runtime test plan as Markdown from a :func:`discriminate` result."""
    plan = disc["needs_runtime"]
    below = disc["below_bar"]
    settled = disc["static_settled"]
    out = [
        "# sec-harness — Red Team Runtime Test Plan",
        "",
        ("_Manual follow-ups: static analysis has taken these as far as source allows. Each "
         "item below is a high-confidence finding whose exploitability must be proven against "
         "the **running** system. The harness does not execute anything — a human runs these._"),
        "",
        f"Confidence bar for inclusion: `risk_score >= {min_risk}`.",
        "",
        "## Prioritization",
        "",
        "| Priority | ID | Class | Risk | Location |",
        "|----------|----|-------|------|----------|",
    ]
    for i, f in enumerate(plan, 1):
        out.append(f"| {i} | {f.id} | {f.cls} | "
                   f"{f.risk_score if f.risk_score is not None else '-'} | {f.file}:{f.line} |")
    out += ["", "## Manual test directives", ""]
    if plan:
        out += [_directive_block(f) for f in plan]
    else:
        out += ["_No confirmed finding requires runtime validation at or above the bar._", ""]
    out += ["## Runtime-validation gaps", "",
            ("_What static analysis could not settle — worth a look with live access, but below "
             "the action bar or not yet finding-grade._"), ""]
    if below:
        for f in below:
            out.append(f"- `{f.id}` ({f.cls}, risk "
                       f"{f.risk_score if f.risk_score is not None else '-'}): {f.message}")
    else:
        out.append("- _none_")
    out += ["", "## Static-settled (no runtime test needed)", "",
            (f"{len(settled)} confirmed finding(s) are source-provable and need no live test; "
             "see the main report.")]
    return "\n".join(out) + "\n"


def write_plan(ws: Workspace, min_risk: int = DEFAULT_MIN_RISK) -> dict:
    """Discriminate the workspace's findings and write ``redteam-plan.md``.

    Args:
        ws: Workspace to read findings from and write the plan into.
        min_risk: Confidence bar for inclusion in the manual plan.

    Returns:
        ``{"plan": <path>, "needs_runtime": n, "below_bar": m, "static_settled": k}``.
    """
    disc = discriminate(read_findings(ws), min_risk)
    ws.reports.mkdir(parents=True, exist_ok=True)
    path = ws.reports / "redteam-plan.md"
    path.write_text(render_plan(disc, min_risk))
    return {
        "plan": str(path),
        "needs_runtime": len(disc["needs_runtime"]),
        "below_bar": len(disc["below_bar"]),
        "static_settled": len(disc["static_settled"]),
    }


def main(argv: list[str] | None = None) -> int:
    """CLI: build the red-team runtime test plan for a workspace."""
    ap = argparse.ArgumentParser(prog="sec-harness-redteam")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--reports-dir", default=None)
    ap.add_argument("--findings-dir", default=None)
    ap.add_argument("--kb-dir", default=None)
    ap.add_argument("--paths-config", default=None)
    ap.add_argument("--min-risk", type=int, default=DEFAULT_MIN_RISK)
    args = ap.parse_args(argv)
    ws = load_paths(workspace=args.workspace, paths_config=args.paths_config,
                    reports_dir=args.reports_dir, findings_dir=args.findings_dir,
                    kb_dir=args.kb_dir)
    result = write_plan(ws, args.min_risk)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
