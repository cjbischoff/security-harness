# Report Readability — Design Spec

**Date:** 2026-08-08
**Status:** design (approved; awaiting user review before writing-plans)
**Motivated by:** `~/Documents/Reports/2026-08-08-aem-report-artifact-critique.md` (AEM run `.sec-harness/aem-analytics-1eec8d50`).
**Scope:** presentation-layer only — the human-facing single-repo report render, the redteam-plan serializer, and the finding-template contract.
**Out of scope:** findings analysis, scoring, `models.py`, `evidence.py`, `go/`, the cross-repo combined-artifacts emitters (B-Plan 3). No new findings; no findings removed.

---

## 1. Problem

The AEM run proved the harness's *analysis* is high-value and accurate but its *presentation* inverts and buries that value:

- `report.md` headline counts confirmed only (`medium: 0`) while 5 `needs-deployment-testing` authz leads exist → a skimming reader sees "nothing serious."
- The 9-section finding template is applied only to the 3 confirmed dep findings (which have no dataflow/CVSS/patch → hollow slots `1,2,5,7` with gaps), and the 5 authz leads bypass it for a bare one-line table.
- The rich per-finding data (dataflow, CVSS, `runtime_test`) lives in `findings/*.json`, unreflected in the narrative.
- `redteam-plan.md` dumps `preconditions`/`expected_signal`/`telemetry` as raw Python `repr`.

Root cause: `references/finding-template.md` is a sound **content contract** but is **completeness-first, not skim-first, and audience-blind** — it has no triage layer — and `report.py` misroutes findings into it.

## 2. Goal & success criteria

Every human-facing artifact leads with the real story, specific and skimmable, no hollow scaffolding.

**Success:**
- A reader opening `report.md` sees, in the first lines, an honest count that tallies confirmed **and** needs-runtime **separately** (never merged, never hidden), and a risk-ordered triage table with the real leads **above** the dep CVEs.
- Each `needs-deployment-testing` finding renders through a purpose-built **NDT-view** (bound to the fields it has: `message`, `dataflow`, `preconditions`, `runtime_test.objective` + secure/insecure signal), foregrounded, and **always labeled needs-runtime** — never laundered into "confirmed."
- Dependency findings render through a **dep-view** (`package@version · advisory · reachability · fix=bump`) — no `(no dataflow)/(no vector)/(no patch)` slots.
- The condensed (medium/low) tier renumbers `1..4` — no leaked gaps from the full skeleton.
- `redteam-plan.md` renders `preconditions`/`expected_signal`/`telemetry` as markdown, not `repr`.
- `references/finding-template.md` is extended so it *is* the contract that meets the readability bar (triage line, NDT-view, dep-view as first-class parts).

**Non-success (explicit):** no change to which findings exist, their status, severity, or score. This is a view change.

## 3. The template becomes the source (extend `finding-template.md`)

Add three first-class views to the template contract, so the rendered report derives from it:

- **Triage line** — one row per finding: `ID · what (one phrase from message) · where (file:line) · status (confirmed | needs-runtime) · next action`. Risk-ordered. This is the skim layer the template lacks.
- **NDT-view** (`needs-deployment-testing`) — condensed, bound to: `message` (what/why-it-matters), `dataflow` (the source-side chain), `preconditions`, and `runtime_test.objective` + `expected_signal.secure/insecure` (the concrete scenario). Deep payloads/telemetry stay in `redteam-plan.md`, linked. Rendered **above** confirmed deps.
- **Dep-view** (`cls == deps`) — `package@version` (from `evidence`), advisory id (`rule_id`/`evidence_sources`), reachability verdict (`reachability.reachable` + `blocker`), fix = "bump to fixed version." No source-flow sections.

The existing full 9-section view (critical/high code-flow findings) and its field-bindings stay as-is. The condensed tier renumbers `1..4`.

## 4. report.md shape (hybrid, leaning B)

`to_markdown` restructures to:

1. **Bottom-line** — one honest sentence + a count block that tallies **confirmed** and **needs-runtime** on separate lines (e.g. `Confirmed: 0 crit/high, 3 low (all dev-only deps) · Needs runtime proof: 5 (2 cross-CE isolation)`).
2. **Triage table** — all findings, risk-ordered, real leads above deps, one triage line each.
3. **Needs runtime proof — the real leads** — NDT-view per finding, foregrounded, linking `redteam-plan.md` for the runnable test.
4. **Confirmed (source-provable)** — dep-view per dep, demoted below the leads.
5. Coverage / limitations sections unchanged.

## 5. redteam-plan.md serializer fix

Where the plan renders `preconditions` (list), `expected_signal` (dict `secure`/`insecure`), and `telemetry` (list), emit markdown — bulleted lists and labeled sub-fields — instead of `str(obj)`. Content is already correct; only the serialization changes.

## 6. Components / files

- `references/finding-template.md` — add triage-line, NDT-view, dep-view sections; renumber condensed tier.
- `helpers/sec_harness/report.py` — `render_finding` (dep-view branch, NDT-view function, renumbered condensed tier), `to_markdown` (bottom-line + triage table + reordered sections).
- `helpers/sec_harness/redteam.py:120-124` — the render site that interpolates `rt['preconditions']` / `rt['expected_signal']` / `rt['telemetry']` raw; replace with markdown serialization (bulleted lists; `secure`/`insecure` as labeled sub-fields).

## 7. Testing

TDD, golden-string tests (stdlib, `uv run pytest`):
- Bottom-line counts confirmed and needs-runtime separately; needs-runtime never shown as 0 when NDT findings exist.
- Triage table risk-ordered, leads above deps.
- NDT-view renders `runtime_test.objective` + secure/insecure signal and is labeled needs-runtime.
- Dep-view has no `(no dataflow)/(no vector)/(no patch)` strings.
- Condensed tier emits `1,2,3,4` with no gap between 2 and the next.
- redteam serializer output contains markdown bullets, not `['` / `{'`.

## 8. Non-goals / YAGNI

- No dual dev/sec-eng documents — the triage layer solves audience-jumping without splitting files.
- No change to the combined-artifacts `FINDINGS.md` (B-Plan 3) — noted as a follow-on to adopt the same triage layer later.
- No new `Finding` fields; no analysis, scoring, or status change.
- No image rendering; mermaid/diagram in architecture is a separate concern.
