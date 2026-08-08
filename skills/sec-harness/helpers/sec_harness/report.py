"""Render findings as SARIF + Markdown; assemble the final report from a workspace."""

from __future__ import annotations

import argparse
import json
from collections import Counter

from sec_harness import cost
from sec_harness.campaign import record_stage
from sec_harness.coverage_ledger import render_markdown as render_coverage_ledger
from sec_harness.evidence import is_tool_receipt
from sec_harness.models import Finding, FindingStatus
from sec_harness.patch_status import PatchStatus, check_patch_applied, not_applied_caution
from sec_harness.sarif import to_sarif
from sec_harness.state import load_state
from sec_harness.workspace import Workspace, load_paths, read_findings

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_REPORTABLE = {FindingStatus.CONFIRMED, FindingStatus.FIXED}


def _risk_sort_key(f: Finding) -> tuple[int, int, str]:
    """Deterministic finding order: risk descending, then severity, then id.

    Used to order both the confirmed and needs-runtime lists and the triage
    table so direct callers (e.g. :func:`select_reportable`) and the report body
    agree. Findings with no ``risk_score`` fall back to severity order.

    Args:
        f: The finding to key.

    Returns:
        A ``(-risk, severity_rank, id)`` sort tuple.
    """
    return (-(f.risk_score or 0), _ORDER.get(f.severity.value, 9), f.id)
# Full template for these tiers; condensed (Summary/Mechanism/Severity/Fix) below.
_FULL_TIERS = {"critical", "high"}


def render_finding(f: Finding, patch_status: PatchStatus | None = None) -> str:
    """Render one finding as the verified-finding template (references/finding-template.md).

    Populated entirely from the Finding JSON fields so the prose never drifts from
    the data. Critical/High get the full 8 sections; Medium/Low get a condensed
    form (Summary, Mechanism, Severity, Fix). Dependency findings get a purpose-built
    dep-view (Summary with package@version, advisory, Reachability, Fix). The harness
    is static-only, so the Confirmation and Attack-Scenario sections are marked as
    static traces.

    Args:
        f: The finding to render.
        patch_status: Result of :func:`patch_status.check_patch_applied` for this
            finding's ``patch_diff`` against the real target, if a target was supplied
            to :func:`write_report`. A ``fixed`` finding not confirmed applied gets a
            caution note — ``verify.py`` only checks a patch against a throwaway copy,
            never the real target.

    Returns:
        A Markdown section string for the finding.
    """
    # Dep-view: early return for dependency findings.
    if f.cls == "deps":
        reach = f.reachability or {}
        rstate = "reachable" if reach.get("reachable") else "not reachable"
        blocker = reach.get("blocker") or "—"
        adv = f.rule_id if f.rule_id.startswith("osv:") else (
            next((s for s in f.evidence_sources if "osv:" in s), f.rule_id))
        pkg = (f.evidence or "").strip() or "(package unknown)"
        out = [f"### {f.id} — deps — {f.severity.value.title()}", "",
               f"**Package.** `{pkg}` — advisory `{adv}`.  ",
               f"Location: `{f.file}:{f.line}`.", "",
               (f"**Reachability.** {rstate} in this repo (blocker: {blocker}). "
                f"{f.message.split('|', 1)[0].strip()}"), "",
               (f"**Fix.** Bump `{pkg.split('@')[0]}` to a release that resolves "
                f"`{adv}`."), ""]
        if f.status is FindingStatus.FIXED and patch_status is not None:
            caution = not_applied_caution(patch_status)
            if caution:
                out.insert(1, caution)   # right after the header line
        return "\n".join(out)

    receipts = [s for s in f.evidence_sources if is_tool_receipt(s)]
    claimed = [s for s in f.evidence_sources if not is_tool_receipt(s)]
    flow = "\n".join(f"   - `{hop}`" for hop in (f.dataflow or [])) or "   - (no dataflow recorded)"
    risk = f.risk_score if f.risk_score is not None else "-"
    verification = f.verification or "static analysis only — not dynamically confirmed"
    patch = (f"```diff\n{f.patch_diff.strip()}\n```" if f.patch_diff
             else "_(no patch generated; remediate per §2 root cause)_")
    full = f.severity.value in _FULL_TIERS

    out = [f"### {f.id} — {f.cls} — {f.severity.value.title()}", ""]
    if f.status is FindingStatus.FIXED and patch_status is not None:
        caution = not_applied_caution(patch_status)
        if caution:
            out += [caution, ""]
    # §1 Summary
    out += [f"**1. Summary.** {f.message}  \nLocation: `{f.file}:{f.line}`.", ""]
    if f.asvs_ids or f.codeguard_ids:
        comp = []
        if f.asvs_ids:
            comp.append("ASVS " + ", ".join(f.asvs_ids))
        if f.codeguard_ids:
            comp.append("CodeGuard " + ", ".join(f.codeguard_ids))
        out += [f"**Compliance.** {'; '.join(comp)}.", ""]
    # §2 Mechanism
    out += ["**2. Mechanism (source).** Data flow:", flow]
    if f.evidence:
        out += ["", f"Sink evidence: `{f.evidence.strip()[:300]}`"]
    out += [""]
    # §3 Confirmation (full tier only)
    if full:
        out += ["**3. Confirmation (static).** Mechanical tool receipts: "
                + (", ".join(f"`{r}`" for r in receipts)
                   or "**NONE — not confirmable on llm-claimed evidence alone**") + ".  "]
        if claimed:
            out += ["Non-receipt / llm-claimed: " + ", ".join(f"`{c}`" for c in claimed) + ".  "]
        out += [f"Verification: `{verification}`.", ""]
        # §4 Impact
        out += [(f"**4. Impact.** Attack class `{f.cls}`; scope per Summary. Assess CIA "
                 "and whether impact is bounded/scriptable per the template."), ""]
    # §5 Severity (full) / §3 Severity (condensed)
    sev_no, fix_no = ("5", "7") if full else ("3", "4")
    out += [(f"**{sev_no}. Severity Rationale.** "
             f"`{f.cvss_vector or '(no vector)'}` — computed risk **{risk}**. "
             "Score computed deterministically from the vector; tier held lower when a "
             "precondition is unproven."), ""]
    if not full:
        out += [("**Confirmation:** "
                 + (", ".join(f"`{r}`" for r in receipts)
                    or "**NONE — not confirmable on llm-claimed evidence alone**") + "."), ""]
    # §6 Attack Scenario (full tier only)
    if full:
        out += [("**6. Confirmed Attack Scenario** (theoretical — not dynamically "
                 "confirmed): follow the §2 data flow from source to sink."), ""]
    # §7 Fix (full) / §4 Fix (condensed)
    out += [f"**{fix_no}. Fix.**", patch, ""]
    # §8 Testing (full tier only)
    if full:
        out += [("**8. Testing.** Negative: the §2 exploit path must return the expected "
                 "rejection post-fix. Regression: legitimate use still works. Static: the "
                 "detector rule must no longer fire in the file."), ""]
    return "\n".join(out)


def render_ndt(f: Finding) -> str:
    """Render a needs-deployment-testing finding as a foregrounded, needs-runtime-labeled view.

    Populated from the fields an NDT finding actually carries — ``message`` (what/why),
    ``dataflow`` (source-side chain), ``preconditions``, and ``runtime_test`` (objective +
    secure/insecure signal). Always labeled needs-runtime and never described as confirmed; the
    runnable payloads/telemetry live in ``redteam-plan.md``.

    Args:
        f: A needs-deployment-testing finding.

    Returns:
        A Markdown section string for the finding.
    """
    rt = f.runtime_test or {}
    sig = rt.get("expected_signal") or {}
    flow = "\n".join(f"  - `{hop}`" for hop in (f.dataflow or [])) or "  - (no source chain recorded)"
    pre = "\n".join(f"  - {p}" for p in (f.preconditions or [])) or "  - (none recorded)"
    out = [f"### {f.id} — {f.cls} — {f.severity.value.title()} · needs runtime proof", "",
           f"**What.** {f.message}  \nLocation: `{f.file}:{f.line}`.", "",
           "**Source-side chain.**", flow, "",
           "**Preconditions (out-of-repo barrier).**", pre, ""]
    if rt.get("objective"):
        out += [f"**Runtime test.** {rt['objective']}"]
        if sig:
            out += [f"  - **secure:** {sig.get('secure', '_unspecified_')}",
                    f"  - **insecure:** {sig.get('insecure', '_unspecified_')}"]
    out += ["_Runnable payloads + telemetry: see `redteam-plan.md`._", ""]
    return "\n".join(out)


def _triage_row(f: Finding, status_label: str, action: str) -> str:
    """Render one triage table row: id, risk, one-clause what, location, status, next action.

    Args:
        f: The finding.
        status_label: ``confirmed`` or ``needs-runtime``.
        action: The next action phrase.

    Returns:
        A single Markdown table row string (pipe-delimited).
    """
    what = (f.message or "").split("|", 1)[0].split(". ")[0].strip()[:80]
    risk = f.risk_score if f.risk_score is not None else "-"
    return f"| {f.id} | {risk} | {what} | {f.file}:{f.line} | {status_label} | {action} |"


def to_markdown(findings: list[Finding], token_spend: dict[str, int] | None = None,
                needs_deployment: list[Finding] | None = None,
                coverage: dict | None = None, coverage_ledger: dict | None = None,
                has_redteam_plan: bool = False,
                patch_statuses: dict[str, PatchStatus] | None = None) -> str:
    """Render findings and optional token accounting as Markdown.

    Structure: Bottom line → Triage table → Needs runtime proof section →
    Confirmed section → Coverage / redteam link / coverage-ledger / token-spend tail.
    NDT findings are NEVER folded into confirmed counts; the ``Needs runtime proof``
    line is never 0 when ``needs_deployment`` is non-empty.

    Args:
        findings: Confirmed/fixed findings to render.
        token_spend: Optional per-phase token totals.
        needs_deployment: Findings real-but-unprovable from source alone. Reported
            separately, never counted as confirmed.
        coverage: Optional ``compute_coverage`` output (``kb/coverage.json``); when given,
            appends a "Coverage & limitations" section so a clean scan carries its
            denominator (O-007/O-033). Omitted entirely when ``None``.
        coverage_ledger: Optional coverage-completeness ledger (``kb/coverage-ledger.json``);
            when given, appends a "Coverage completeness" section. Omitted when ``None``.
        has_redteam_plan: True when ``redteam-plan.md`` exists in the reports dir; adds a
            "Manual runtime testing" section pointing the engineer at it (O-022).
        patch_statuses: Optional ``finding.id`` → :class:`PatchStatus`, from
            :func:`check_patch_applied` against the real target, for ``fixed`` findings.

    Returns:
        A Markdown report string.
    """
    ndt = sorted(needs_deployment or [], key=_risk_sort_key)
    conf = sorted(findings, key=_risk_sort_key)

    # Bottom line — confirmed counts exclude NDT entirely (epistemic honesty)
    conf_counts = Counter(f.severity.value for f in findings)
    crit = conf_counts.get("critical", 0)
    high = conf_counts.get("high", 0)
    med = conf_counts.get("medium", 0)
    low = conf_counts.get("low", 0)
    total_conf = sum(conf_counts.values())
    if total_conf == 0:
        summary_sentence = "No source-provable findings."
    elif crit or high:
        summary_sentence = f"{'Critical' if crit else 'High'}-severity source-provable findings require immediate remediation."
    else:
        summary_sentence = "Source-provable findings at medium/low severity."
    lines = [
        "# sec-harness Report", "",
        f"**Bottom line.** {summary_sentence}  ",
        f"Confirmed: {crit}/{high}/{med}/{low}",
        f"Needs runtime proof: {len(ndt)}",
        "",
    ]

    # Triage table — all findings merged, risk-ordered desc
    all_triage = (
        [(f, "needs-runtime",
          "run redteam-plan test") for f in ndt]
        + [(f, "confirmed",
            "bump" if f.cls == "deps" else "apply fix (§ below)") for f in conf]
    )
    all_triage.sort(key=lambda t: _risk_sort_key(t[0]))
    lines += [
        "## Triage", "",
        "| ID | Risk | What | Location | Status | Next action |",
        "|----|------|------|----------|--------|-------------|",
    ]
    for f, status_label, action in all_triage:
        lines.append(_triage_row(f, status_label, action))
    lines.append("")

    # Needs runtime proof section (NDT only, leads above confirmed)
    if ndt:
        lines += ["## Needs runtime proof — the real leads", ""]
        for f in ndt:
            lines += [render_ndt(f), "---", ""]

    # Confirmed section
    if conf:
        lines += ["## Confirmed (source-provable)", ""]
        for f in conf:
            lines += [render_finding(f, patch_status=(patch_statuses or {}).get(f.id)),
                      "---", ""]

    if coverage:
        lines += ["", "## Coverage & limitations", "",
                  ("_SAST coverage by language. `none` = no mechanical dataflow OR pattern "
                   "analysis (LLM shape-hunting only)._"), "",
                  "| Language | Files | Tier |", "|----------|-------|------|"]
        for lang in coverage.get("languages", []):
            lines.append(f"| {lang['language']} | {lang['files']} | {lang['tier']} |")
        uncovered = ", ".join(coverage.get("uncovered", [])) or "none"
        lines += ["", (f"Dataflow coverage: {coverage.get('dataflow_pct', 0)}% of counted "
                       f"source. Uncovered (LLM-only): {uncovered}.")]
    if has_redteam_plan:
        lines += ["", "## Manual runtime testing", "",
                  ("See `redteam-plan.md` for the runtime test directives "
                   "(needs-runtime findings).")]
    if coverage_ledger:
        lines += ["", render_coverage_ledger(coverage_ledger)]
    if token_spend:
        lines += ["", "## Token spend by phase", ""]
        lines += [f"- **{phase}**: {n}" for phase, n in token_spend.items()]
    return "\n".join(lines) + "\n"


def select_reportable(findings: list[Finding]) -> list[Finding]:
    """Select findings suitable for the final report.

    Keeps only ``CONFIRMED``/``FIXED`` findings, ordered by :func:`_risk_sort_key`
    (risk descending, then severity, then id) so the reportable order matches the
    report body's triage/confirmed ordering.

    Args:
        findings: All findings in the workspace.

    Returns:
        The reportable subset, highest-risk first.
    """
    reportable = [f for f in findings if f.status in _REPORTABLE]
    return sorted(reportable, key=_risk_sort_key)


def write_report(ws: Workspace, *, target: str | None = None) -> dict:
    """Assemble the final SARIF + Markdown report from a workspace's findings.

    Overwrites ``report.sarif``, ``report.md``, and ``findings.json`` so they
    reflect the finished analysis rather than prefilter-time candidates.
    ``findings.json`` carries confirmed/fixed findings plus needs-deployment-testing
    findings (distinguished by status); SARIF carries confirmed/fixed only.

    Args:
        ws: Workspace to read findings from and write reports into.
        target: Path to the real target repo. When given, ``fixed`` findings are mechanically
            checked (``git apply --check``) against the real working tree so the report never
            implies a still-vulnerable finding's patch is deployed.

    Returns:
        ``{"reported": <count>, "sarif": <path>, "report": <path>}``.
    """
    all_findings = read_findings(ws)
    reportable = select_reportable(all_findings)
    ndt = [f for f in all_findings if f.status is FindingStatus.NEEDS_DEPLOYMENT_TESTING]
    coverage_path = ws.kb / "coverage.json"
    coverage = json.loads(coverage_path.read_text()) if coverage_path.exists() else None
    cl_path = ws.kb / "coverage-ledger.json"
    if not cl_path.exists():
        from sec_harness.coverage_ledger import build_coverage_ledger  # local: avoid cycle
        build_coverage_ledger(ws)
    coverage_ledger = json.loads(cl_path.read_text()) if cl_path.exists() else None
    has_redteam_plan = (ws.reports / "redteam-plan.md").exists()
    token_spend = cost.aggregate_by_phase(load_state(ws)) or None
    patch_statuses = None
    if target:
        patch_statuses = {
            f.id: check_patch_applied(target, f.patch_diff)
            for f in reportable if f.status is FindingStatus.FIXED and f.patch_diff
        }
    ws.sarif_path.write_text(json.dumps(to_sarif(reportable), indent=2))
    ws.report_path.write_text(to_markdown(reportable, token_spend=token_spend, needs_deployment=ndt,
                                          coverage=coverage,
                                          coverage_ledger=coverage_ledger,
                                          has_redteam_plan=has_redteam_plan,
                                          patch_statuses=patch_statuses))
    findings_out = reportable + ndt
    ws.findings_json_path.write_text(json.dumps([f.to_dict() for f in findings_out], indent=2))
    record_stage(ws, "report")
    return {"reported": len(reportable), "sarif": str(ws.sarif_path), "report": str(ws.report_path)}


def main(argv: list[str] | None = None) -> int:
    """CLI: assemble the final report for a workspace.

    Args:
        argv: Optional argument vector.

    Returns:
        0 on success.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-report")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--reports-dir", default=None)
    parser.add_argument("--findings-dir", default=None)
    parser.add_argument("--kb-dir", default=None)
    parser.add_argument("--paths-config", default=None)
    parser.add_argument("--target", default=None)
    args = parser.parse_args(argv)
    ws = load_paths(workspace=args.workspace, paths_config=args.paths_config,
                    reports_dir=args.reports_dir, findings_dir=args.findings_dir,
                    kb_dir=args.kb_dir)
    result = write_report(ws, target=args.target)
    print(f"reported {result['reported']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
