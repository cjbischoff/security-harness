"""Render findings as SARIF + Markdown; assemble the final report from a workspace."""

from __future__ import annotations

import argparse
import json
from collections import Counter

from sec_harness.evidence import is_tool_receipt
from sec_harness.models import Finding, FindingStatus
from sec_harness.sarif import to_sarif
from sec_harness.workspace import Workspace, load_paths, read_findings

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_REPORTABLE = {FindingStatus.CONFIRMED, FindingStatus.FIXED}
# Full template for these tiers; condensed (Summary/Mechanism/Severity/Fix) below.
_FULL_TIERS = {"critical", "high"}


def render_finding(f: Finding) -> str:
    """Render one finding as the verified-finding template (references/finding-template.md).

    Populated entirely from the Finding JSON fields so the prose never drifts from
    the data. Critical/High get the full 9 sections; Medium/Low get a condensed
    form (Summary, Mechanism, Severity, Fix). The harness is static-only, so the
    Confirmation and Attack-Scenario sections are marked as static traces.

    Args:
        f: The finding to render.

    Returns:
        A Markdown section string for the finding.
    """
    receipts = [s for s in f.evidence_sources if is_tool_receipt(s)]
    claimed = [s for s in f.evidence_sources if not is_tool_receipt(s)]
    flow = "\n".join(f"   - `{hop}`" for hop in (f.dataflow or [])) or "   - (no dataflow recorded)"
    risk = f.risk_score if f.risk_score is not None else "-"
    verification = f.verification or "static analysis only — not dynamically confirmed"
    patch = (f"```diff\n{f.patch_diff.strip()}\n```" if f.patch_diff
             else "_(no patch generated; remediate per §2 root cause)_")
    full = f.severity.value in _FULL_TIERS

    out = [f"### {f.id} — {f.cls} — {f.severity.value.title()}", ""]
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
    # §5 Severity
    out += [("**5. Severity Rationale.** "
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
    # §7 Fix
    out += ["**7. Fix.**", patch, ""]
    # §8 Testing (full tier only)
    if full:
        out += [("**8. Testing.** Negative: the §2 exploit path must return the expected "
                 "rejection post-fix. Regression: legitimate use still works. Static: the "
                 "detector rule must no longer fire in the file."), ""]
    return "\n".join(out)


def to_markdown(findings: list[Finding], token_spend: dict[str, int] | None = None,
                needs_deployment: list[Finding] | None = None,
                coverage: dict | None = None, has_redteam_plan: bool = False) -> str:
    """Render findings and optional token accounting as Markdown.

    The findings table includes Risk (calibrated 1-10 score) and Verification
    columns; missing values render as ``-``.

    Args:
        findings: Findings to render.
        token_spend: Optional per-phase token totals.
        needs_deployment: Findings real-but-unprovable from source alone.
        coverage: Optional ``compute_coverage`` output (``kb/coverage.json``); when given,
            appends a "Coverage & limitations" section so a clean scan carries its
            denominator (O-007/O-033). Omitted entirely when ``None``.
        has_redteam_plan: True when ``redteam-plan.md`` exists in the reports dir; adds a
            "Manual runtime testing" section pointing the engineer at it (O-022).

    Returns:
        A Markdown report string.
    """
    ordered = sorted(findings, key=lambda f: (_ORDER[f.severity.value], f.id))
    counts = Counter(f.severity.value for f in findings)
    lines = ["# sec-harness Report", "", "## Summary", ""]
    lines += [f"- **{sev}**: {counts.get(sev, 0)}" for sev in _ORDER]
    lines += ["", "## Findings", "",
              "| ID | Class | Severity | Risk | Location | Verification | Message |",
              "|----|-------|----------|------|----------|--------------|---------|"]
    for f in ordered:
        risk = f.risk_score if f.risk_score is not None else "-"
        verification = f.verification if f.verification is not None else "-"
        lines.append(
            f"| {f.id} | {f.cls} | {f.severity.value} | {risk} | "
            f"{f.file}:{f.line} | {verification} | {f.message} |"
        )
    if ordered:
        lines += ["", "## Detailed findings", ""]
        for f in ordered:
            lines += [render_finding(f), "---", ""]
    if needs_deployment:
        # F9: real-but-unprovable-from-source — reported separately, NOT confirmed,
        # NOT a false positive. Never fudge these into the confirmed count/severity.
        lines += ["", "## Needs deployment testing (unconfirmable from source)", "",
                  ("_Real leads whose confirmation requires infra/config/secrets not in "
                   "the repo. Verify in a deployed environment; not counted as confirmed._"),
                  "",
                  "| ID | Class | Severity | Location | Why unconfirmable |",
                  "|----|-------|----------|----------|-------------------|"]
        for f in sorted(needs_deployment, key=lambda f: f.id):
            lines.append(f"| {f.id} | {f.cls} | {f.severity.value} | "
                         f"{f.file}:{f.line} | {f.message} |")
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
    if token_spend:
        lines += ["", "## Token spend by phase", ""]
        lines += [f"- **{phase}**: {n}" for phase, n in token_spend.items()]
    return "\n".join(lines) + "\n"


def select_reportable(findings: list[Finding]) -> list[Finding]:
    """Select findings suitable for the final report.

    Keeps only ``CONFIRMED``/``FIXED`` findings, sorted by descending risk score
    (missing score treated as 0), then id.

    Args:
        findings: All findings in the workspace.

    Returns:
        The reportable subset, highest-risk first.
    """
    reportable = [f for f in findings if f.status in _REPORTABLE]
    return sorted(reportable, key=lambda f: (-(f.risk_score or 0), f.id))


def write_report(ws: Workspace) -> dict:
    """Assemble the final SARIF + Markdown report from a workspace's findings.

    Overwrites ``report.sarif``, ``report.md``, and ``findings.json`` so they
    reflect the finished analysis (confirmed/fixed findings) rather than
    prefilter-time candidates.

    Args:
        ws: Workspace to read findings from and write reports into.

    Returns:
        ``{"reported": <count>, "sarif": <path>, "report": <path>}``.
    """
    all_findings = read_findings(ws)
    reportable = select_reportable(all_findings)
    ndt = [f for f in all_findings if f.status is FindingStatus.NEEDS_DEPLOYMENT_TESTING]
    coverage_path = ws.kb / "coverage.json"
    coverage = json.loads(coverage_path.read_text()) if coverage_path.exists() else None
    has_redteam_plan = (ws.reports / "redteam-plan.md").exists()
    ws.sarif_path.write_text(json.dumps(to_sarif(reportable), indent=2))
    ws.report_path.write_text(to_markdown(reportable, needs_deployment=ndt, coverage=coverage,
                                          has_redteam_plan=has_redteam_plan))
    ws.findings_json_path.write_text(json.dumps([f.to_dict() for f in reportable], indent=2))
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
    args = parser.parse_args(argv)
    ws = load_paths(workspace=args.workspace, paths_config=args.paths_config,
                    reports_dir=args.reports_dir, findings_dir=args.findings_dir,
                    kb_dir=args.kb_dir)
    result = write_report(ws)
    print(f"reported {result['reported']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
