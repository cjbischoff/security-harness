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

from sec_harness.campaign import record_stage
from sec_harness.evidence import is_tool_receipt
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.patch_status import PatchStatus, check_patch_applied, not_applied_caution
from sec_harness.phase_gate import GateDecision, build_gate_record, write_gate_record
from sec_harness.workspace import Workspace, load_paths, read_findings

DEFAULT_MIN_RISK = 7
_REPORTABLE = {FindingStatus.CONFIRMED, FindingStatus.FIXED}
_ACTIONABLE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
_SEV_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def wants_runtime(f: Finding) -> bool:
    """True if a finding's exploitability can only be settled by testing the running system."""
    return f.runtime_disposition == "needs-runtime" or f.status is FindingStatus.NEEDS_DEPLOYMENT_TESTING


def _above_bar(f: Finding, min_risk: int) -> bool:
    """A needs-runtime finding is actionable if its severity is >= medium, else gated by min_risk.

    Fixes O-016/O-031: min_risk can no longer hide a confirmed critical/high whose deterministic
    risk_score sits low. Fixes the LEAD/doc-lead flood: the severity pass also requires a tool
    receipt, so an llm-claimed-only carrier can't bypass min_risk on severity alone.
    """
    has_receipt = any(is_tool_receipt(s) for s in f.evidence_sources)
    if f.severity in _ACTIONABLE_SEVERITIES and has_receipt:
        return True
    if any(h.get("event") == "redteam:prime-manual-test" for h in f.history):
        return True
    return (f.risk_score or 0) >= min_risk


def discriminate(findings: list[Finding], min_risk: int = DEFAULT_MIN_RISK) -> dict:
    """Partition findings for the runtime plan.

    Considers confirmed/fixed findings plus ``needs-deployment-testing`` leads. A needs-runtime
    candidate of critical/high/medium severity always reaches the plan; a low-severity candidate
    reaches it only if its ``risk_score`` meets ``min_risk`` (signal over noise).

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
        return (-(f.risk_score or 0), -_SEV_RANK.get(f.severity, 0), f.id)

    return {
        "needs_runtime": sorted(plan, key=key),
        "static_settled": sorted(static_settled, key=key),
        "below_bar": sorted(below_bar, key=key),
    }


def _bullets(items: object) -> str:
    """Render a list of strings as indented markdown bullets.

    Args:
        items: A list of strings, or any other value.

    Returns:
        Newline-joined ``  - <item>`` bullets for a list, a single ``  - <s>``
        bullet for a non-empty string, or ``_not specified_`` otherwise.
    """
    if isinstance(items, list) and items:
        return "\n".join(f"  - {x!s}" for x in items)
    if isinstance(items, str) and items.strip():
        return f"  - {items}"
    return "_not specified_"


def _signal(d: object) -> str:
    """Render an expected-signal dict as labeled secure/insecure sub-fields.

    Args:
        d: A dict with ``secure``/``insecure`` keys, or any other value.

    Returns:
        Two indented ``**secure:** …`` / ``**insecure:** …`` lines for a dict,
        an inline `` <s>`` for a non-empty string, or `` _not specified_``.
    """
    if isinstance(d, dict) and d:
        return (f"\n  - **secure:** {d.get('secure', '_unspecified_')}"
                f"\n  - **insecure:** {d.get('insecure', '_unspecified_')}")
    if isinstance(d, str) and d.strip():
        return f" {d}"
    return " _not specified_"


def _directive_block(f: Finding, patch_status: PatchStatus | None = None) -> str:
    """Render one manual runtime-test directive from a finding's ``runtime_test`` block.

    Args:
        f: The finding to render a directive for.
        patch_status: Result of :func:`patch_status.check_patch_applied` for this finding's
            ``patch_diff`` against the real target, if a target was supplied to
            :func:`write_plan`. A deterministic backstop against the producer agent framing a
            still-vulnerable finding's ``runtime_test`` as if the deployed fix were live.
    """
    rt = f.runtime_test or {}
    receipts = [s for s in f.evidence_sources if is_tool_receipt(s)]
    payloads = rt.get("payloads") or []
    payload_md = "\n".join(f"  - `{p}`" for p in payloads) if payloads else "  - _(none supplied)_"
    lines = [
        f"### {f.id} — {f.cls} — risk {f.risk_score if f.risk_score is not None else '-'}",
        "",
    ]
    if f.status is FindingStatus.FIXED and patch_status is not None:
        caution = not_applied_caution(patch_status)
        if caution:
            lines += [caution, ""]
    lines += [
        f"- **Objective:** {rt.get('objective', f.message)}",
        f"- **Preconditions / access:**\n{_bullets(rt.get('preconditions'))}",
        "- **Payload(s)** (shell vars only — export before use):",
        payload_md,
        f"- **Expected signal:**{_signal(rt.get('expected_signal'))}",
        f"- **Telemetry to watch:**\n{_bullets(rt.get('telemetry'))}",
        f"- **Static evidence:** `{f.file}:{f.line}` — "
        + (", ".join(f"`{r}`" for r in receipts) or "_no tool receipt (verify carefully)_"),
        "",
    ]
    return "\n".join(lines)


def render_plan(
    disc: dict, min_risk: int = DEFAULT_MIN_RISK,
    patch_statuses: dict[str, PatchStatus] | None = None,
) -> str:
    """Render the manual runtime test plan as Markdown from a :func:`discriminate` result.

    Args:
        disc: Output of :func:`discriminate`.
        min_risk: Confidence bar for inclusion in the manual plan (used only in the header text).
        patch_statuses: Optional ``finding.id`` → :class:`PatchStatus`, from
            :func:`check_patch_applied` against the real target, for ``fixed`` findings —
            rendered as a caution on the affected directive block.
    """
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
        (f"Included: needs-runtime findings of critical/high/medium severity, plus low-severity "
         f"with `risk_score >= {min_risk}`."),
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
        code_settled = [f for f in plan if f.dataflow and f.preconditions]
        incomplete = [f for f in plan if not (f.dataflow and f.preconditions)]
        for heading, group in (("Code-settled, runtime-impact-pending", code_settled),
                               ("Verification-incomplete", incomplete)):
            out.append(f"### {heading}")
            out.append("")
            out += [_directive_block(f, patch_status=(patch_statuses or {}).get(f.id))
                    for f in group] if group else ["_none_", ""]
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


def build_redteam_gate_record(findings: list[Finding], verdicts: dict[str, str] | None = None) -> dict:
    """Assemble the redteam phase gate record from needs-runtime findings.

    Each finding is already tool-receipt gated upstream (critic/judge/validate), so this skips
    :func:`phase_gate.ref_resolves` and sends every finding straight to the adversary.

    Args:
        findings: Needs-runtime findings entering the manual test plan.
        verdicts: Optional ``finding.id`` → adversary verdict
            (``CONFIRMED`` / ``WEAKENED`` / ``INVALIDATED``).

    Returns:
        A gate record in the same shape :func:`phase_gate.build_gate_record` produces.
    """
    decisions = [
        GateDecision(claim_id=f.id, status="to-adversary", refs=[f"{f.file}:{f.line}"],
                     text=f.message)
        for f in findings
    ]
    return build_gate_record("redteam", decisions, verdicts)


def _fixed_patch_statuses(findings: list[Finding], target: str) -> dict[str, PatchStatus]:
    """Check real-target patch-application state for every ``fixed`` finding with a patch_diff.

    Args:
        findings: Findings to check (only ``FIXED`` ones with a non-empty ``patch_diff`` count).
        target: Path to the real target repo's working tree.

    Returns:
        ``finding.id`` → :class:`PatchStatus`, one entry per checked finding.
    """
    statuses: dict[str, PatchStatus] = {}
    for f in findings:
        if f.status is FindingStatus.FIXED and f.patch_diff:
            statuses[f.id] = check_patch_applied(target, f.patch_diff)
    return statuses


def write_plan(ws: Workspace, min_risk: int = DEFAULT_MIN_RISK, *, target: str | None = None) -> dict:
    """Discriminate the workspace's findings and write ``redteam-plan.md``.

    Args:
        ws: Workspace to read findings from and write the plan into.
        min_risk: Confidence bar for inclusion in the manual plan.
        target: Path to the real target repo. When given, ``fixed`` findings are mechanically
            checked (``git apply --check``) against the real working tree so a runtime-test
            directive never gets framed as if a still-vulnerable fix were deployed.

    Returns:
        ``{"plan": <path>, "needs_runtime": n, "below_bar": m, "static_settled": k}``.
    """
    findings = read_findings(ws)
    disc = discriminate(findings, min_risk)
    patch_statuses = _fixed_patch_statuses(findings, target) if target else None
    ws.reports.mkdir(parents=True, exist_ok=True)
    path = ws.reports / "redteam-plan.md"
    path.write_text(render_plan(disc, min_risk, patch_statuses=patch_statuses))
    write_gate_record(ws, "redteam", build_redteam_gate_record(disc["needs_runtime"]))
    record_stage(ws, "redteam")
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
    ap.add_argument("--target", default=None)
    args = ap.parse_args(argv)
    ws = load_paths(workspace=args.workspace, paths_config=args.paths_config,
                    reports_dir=args.reports_dir, findings_dir=args.findings_dir,
                    kb_dir=args.kb_dir)
    result = write_plan(ws, args.min_risk, target=args.target)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
