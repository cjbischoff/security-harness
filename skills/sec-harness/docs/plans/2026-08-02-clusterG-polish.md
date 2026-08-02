# Cluster G — Report / Plan / Wiring Polish (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Close the report/plan/wiring gaps that make the output mildly misleading or leave earlier fixes inert: link the red-team plan from the report, show receipts in the condensed report tier, carry non-Finding leads into the plan, stamp pass-through audit events, and wire the Cluster B/C extractors + reconcile the doc ordering.

**Architecture:** Small, independent edits. Task 1 (code): report links redteam-plan.md + condensed-tier receipts row. Task 2 (code): a `manual_review_findings` LEAD carrier mirroring the existing `control_findings`. Task 3 (prose): critic pass-event, SKILL wiring of the extractors + `demote_noise`/`reconcile_plan`/`promote_runtime_dependent`, and the C1/recon doc-ordering reconcile.

**Tech Stack:** Python 3.13 stdlib-only, pytest/ruff/ty. Run from `skills/sec-harness/helpers/`.

## Global Constraints
- stdlib-only; line 100; ruff+ty clean on changed files.
- Evidence: O-022/O-023 (report drops receipts / no plan link), O-020 (non-Finding leads dropped), O-012 (no pass audit trail), O-004-wiring + O-000 (doc ordering).
- Branch `skill-audit-driver-20260731`; stage only `skills/` paths; never `git add -A`.

---

### Task 1: report links redteam-plan.md + condensed-tier receipts

**Files:** Modify `helpers/sec_harness/report.py`. Test: `helpers/tests/test_report.py`.

- [ ] **Step 1: failing test** — a report for a workspace containing a `redteam-plan.md` and a confirmed medium finding (with an evidence receipt) mentions the plan and shows the receipt in the finding's condensed section:
```python
def test_report_links_redteam_plan_and_shows_receipts(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.workspace import Workspace, write_findings
    from sec_harness.report import write_report
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    (ws.reports).mkdir(parents=True, exist_ok=True)
    (ws.reports / "redteam-plan.md").write_text("# plan\n")
    write_findings(ws, [Finding(id="F-1", rule_id="r", cls="authz", status=FindingStatus.CONFIRMED,
                                severity=Severity.MEDIUM, file="a.py", line=1, message="m",
                                risk_score=5, evidence_sources=["ripgrep:a.py:1"])])
    write_report(ws)
    md = (ws.reports / "report.md").read_text()
    assert "redteam-plan.md" in md            # T11a: link the manual test plan
    assert "ripgrep:a.py:1" in md             # T11b: receipts visible even in condensed (medium) tier
```
- [ ] **Step 2: run FAIL**.
- [ ] **Step 3: implement** — in report.py: (a) in the condensed per-finding render (medium/low), add a one-line `**Confirmation:** <tool receipts>` row listing `evidence_sources` entries that pass `evidence.is_tool_receipt` (import it). (b) In `to_markdown`/`write_report`, if `ws.reports / "redteam-plan.md"` exists, append a section: `## Manual runtime testing\n\nSee \`redteam-plan.md\` for the runtime test directives (needs-runtime findings).` Match the existing render style.
- [ ] **Step 4: run PASS** (+ existing test_report.py green).
- [ ] **Step 5: lint** report.py + test.
- [ ] **Step 6: commit** — `git commit -m "feat(report): link redteam-plan + show receipts in condensed tier (O-022/O-023)"` (stage report.py + test).

---

### Task 2: LEAD carrier for non-Finding leads

**Files:** Modify `helpers/sec_harness/context.py` (add `manual_review_findings`). Test: `helpers/tests/test_context.py`.

**Interfaces:** `manual_review_findings(ctx, sha: str) -> list[Finding]` — one `LEAD-####` finding (status `NEEDS_DEPLOYMENT_TESTING`, `cls="manual-review"`, evidence `["llm-claimed:doc-lead"]`) per context `attack_lead` item, so out-of-band leads (CI deploy-token) reach the red-team plan's manual section instead of vanishing.

- [ ] **Step 0: read the existing `context.control_findings`** (same module) — it already emits `CTL-####` findings from claimed_controls. MIRROR its structure exactly (id numbering, how it reads ctx items, how it builds a Finding), changing: source item kind = `attack_lead` (not claimed_control), id prefix `LEAD-`, status `NEEDS_DEPLOYMENT_TESTING`, cls `manual-review`, evidence `llm-claimed:doc-lead`. Use the real ContextItem attribute names (`text` for the summary, `where` for the location — verified in Cluster C).
- [ ] **Step 1: failing test** — build a Context with one `attack_lead` item and assert `manual_review_findings` yields one `LEAD-0001` finding with the right status/cls. (Model the Context construction on the existing `test_context.py` fixtures.)
- [ ] **Step 2: run FAIL**.
- [ ] **Step 3: implement** `manual_review_findings` mirroring `control_findings`.
- [ ] **Step 4: run PASS**; **Step 5: lint** context.py + test.
- [ ] **Step 6: commit** — `git commit -m "feat(context): LEAD carrier so non-Finding leads reach the redteam plan (O-020)"` (stage context.py + test).

---

### Task 3: prose — audit event, wiring, doc reconcile

**Files:** `skills/sec-harness/agents/critic.md`, `skills/sec-harness/SKILL.md`, `skills/sec-harness/CLAUDE.md`. No test.

- [ ] **Step 1: critic.md (T14)** — in the Decide/Output rules, add: "On a finding you keep viable, append a history event `{\"event\": \"critic:viable\"}` (a positive audit trail) — so 'reviewed & passed' is distinguishable from 'never reviewed'."
- [ ] **Step 2: SKILL.md wiring** — in Phase 0-1/C1, note that the orchestrator builds gate claims via `phase_gate.claims_from_profile(profile)` / `claims_from_context(ctx)` (Cluster C) rather than hand-rolling them. In C1, note `manual_review_findings(ctx, sha)` emits `LEAD-####` records. Confirm the Phase 2-3 `demote_noise`/`reconcile_plan` note (Cluster B) and the Phase 5.5 `promote_runtime_dependent` note (Cluster D) are present (add if a prior cluster's wiring didn't land).
- [ ] **Step 3: doc reconcile (T16/O-000)** — make SKILL.md and CLAUDE.md agree on C1 ordering. Canonical order: **C1 context-ingest runs after preflight, BEFORE recon** (its leads feed recon; a recon attack_surface class may be added from a lead only if a code indicator exists). Fix whichever doc states otherwise so both read the same.
- [ ] **Step 4: commit** — `git add skills/sec-harness/agents/critic.md skills/sec-harness/SKILL.md skills/sec-harness/CLAUDE.md && git commit -m "docs(sec-harness): critic pass-event, extractor/LEAD wiring, C1 ordering reconcile (O-012/O-000)"`

---

## Self-review
- Spec coverage: GSD Cluster G → Task 1 (T11 report link+receipts), Task 2 (T12 LEAD carrier), Task 3 (T14 audit event, T16 doc reconcile, + Cluster B/C/D wiring notes). ✓
- Non-breaking: report additions only appear when the relevant data exists; LEAD carrier is a new function (no caller change forced). ✓
- Deferred (noted, low-value): patch `fix_disposition` schema migration (T11c) — the current free-form patch_diff + verify's graceful git-apply-failure already degrade acceptably; revisit if patch output becomes structured elsewhere.
