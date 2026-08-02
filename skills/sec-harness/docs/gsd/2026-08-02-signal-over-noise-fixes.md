# GSD — sec-harness signal-over-noise correctness fixes

**Date:** 2026-08-02 · **Author:** audit-driver session · **Status:** design (approved direction)

## Why this exists

Running the harness end-to-end on 4 real codebases (flamingo-shopify-app, coterie-backend full;
flamingo-shopify, mando light) produced 34 logged observations. The KB-reasoning + adversarial-diversity
spine works: it found real, exploitable, high-severity bugs SAST cannot (unauth order cancel/refund, NoSQL
auth-bypass, webhook signature bypass, hardcoded-key→OTP chain, sibling discount-injection). The findings
are **accurate**. What degrades "signal over noise / accurate valuable info to the security team" is
**presentation, routing, and a few robustness gaps** — concentrated in the fixes below.

Evidence refs (O-###) point to the observation log for the failing run that motivated each fix.

Guiding principle: **the harness must never mislead a security engineer about what is most important or what
was covered.** A confirmed critical must rank as critical; a clean scan must state its coverage denominator;
a runtime-only finding must reach the test plan.

---

## Cluster A — Prioritization & risk correctness  (P1)

### Defect (O-031, O-015, O-016)
`risk_score` inverts against severity. On coterie-backend: committed QA secrets (medium) → risk 8; unauth
order cancel/refund (critical) → risk 7; **NoSQL auth-bypass (critical) → risk 5, below the red-team
`min-risk 7` bar → dropped into "gaps."** A security engineer reading the prioritized plan sees medium
secrets on top and misses the critical auth-bypass. Root cause: `calibrate._precondition_cap(len(precons))`
hard-caps by precondition COUNT (3+ → 5) regardless of severity, and easily-met preconditions ("unauth")
count the same as real barriers — so thorough precondition enumeration *penalizes* a finding.

### Direction / reasoning
Risk is a *communication* device for humans. Two invariants: (1) a critical must never sort below a
medium; (2) a "precondition" that an attacker meets for free is not a mitigant and must not lower risk. We
keep the deterministic CVSS computation (LLMs never assert a number) but fix the two distortions and make
the red-team action bar reflect *actionability*, not a raw number.

### Changes (all three — approved)
1. **Difficulty-weighted preconditions** — replace `_precondition_cap(n: int)` with
   `_precondition_cap(preconditions: list[str])` that classifies each string:
   - *non-mitigant* (weight 0): matches `unauth`, `unauthenticated`, `no auth`, `no config`, `default
     config`, `public`, `remote`, `any user`, `anonymous`.
   - *weak* (counts 0.5): `authenticated`, `logged in`, `one hop`, `valid session`, `any account`.
   - *strong* (counts 1.0): `admin`, `operator`, `non-default config`, `feature flag`, `local access`,
     `prior primitive`, `physical`, `MITM`, `specific/guessed id`.
   Cap tiers apply to the *summed weight*, not the raw count: `Σw < 1 → no cap`, `1 ≤ Σw < 3 → cap 8/7`,
   `Σw ≥ 3 → cap 5`. Keyword map lives in a module constant so it's auditable + testable.
2. **Severity floor** — after the cap, `raw = max(raw, _severity_floor(f.severity))` with
   `{critical: 8, high: 6, medium: 4, low: 2, info: 1}`. Guarantees severity ordering is never inverted.
   (A finding whose CVSS/severity disagree is a data defect surfaced by `inflation_delta`, not silently
   averaged.)
3. **Disposition-aware red-team bar** — in `redteam.py`, an item is an **actionable directive** iff
   `runtime_disposition == "needs-runtime"` AND `severity ∈ {critical, high, medium}`; low-severity
   needs-runtime is gated by `--min-risk` (into "gaps"). `min-risk` stops being able to hide a
   critical/high. Static-settled and below-bar items render as before.

### Files
`sec_harness/calibrate.py` (`_precondition_cap`, `calibrate_score`, new `_severity_floor`, keyword consts);
`sec_harness/redteam.py` (`discriminate`/bar logic + the plan renderer's directive-vs-gap split).

### Tests (TDD, red first)
- `test_calibrate.py`: critical never scores below medium (the exact O-031 fixtures: NoSQL-ATO critical
  with 3 unauth-ish preconditions must score ≥8; committed-QA-secret medium must not exceed it).
- unauth-only preconditions do not lower risk; a real "requires admin token" precondition does.
- `test_redteam.py`: a confirmed critical needs-runtime enters directives at `min-risk 7`; a low
  needs-runtime does not.

### Acceptance
Re-render coterie-backend's plan: the 3 criticals sit above all mediums; C-0107 is an actionable directive.

---

## Cluster B — SAST routing & noise  (P1)

### Defect (O-025, O-027, O-030)
91% (backend) / 81% (frontend) of prefilter candidates are *unrouted* — no investigate agent. The
general-triage "safety net" carries the load and is recall-biased, flooding ~76 raw noise findings.
Vendored rules emit classes the catalog never maps (`unknown`, `log-injection`, `security-other`,
`clear-text-logging`); recon omits sqli/xss but semgrep flags them; SAST flags the *safe* instances
(rate-limit on already-auth routes) and misses the dangerous ones. Yet CodeQL dataflow *is* valuable — it
found the 2 NoSQL criticals (O-028). So: keep SAST, fix routing + noise.

### Direction / reasoning
Two failure modes to separate: (a) real-signal classes that lack an agent (codeql sqli/ssrf/path-traversal)
→ must be routed to a real investigator; (b) low-value vendored noise (log-injection, clear-text-logging,
CWE-less "unknown") → must NOT be promoted to `raw` and flood the ladder. The plan can't be fixed at recon
time (candidates don't exist yet) — reconcile *after* the prefilter.

### Changes
1. **Post-prefilter re-plan** — new deterministic `partition.reconcile_plan(ws, profile) -> updated
   agents_to_spawn` run after `run_prefilter`: for every candidate class carrying real security weight
   (via `clsmap`), ensure an agent exists (either the per-class agent or an explicit `security-other`
   general-triage). Log what it added. Orchestrator + SKILL step updated.
2. **`clsmap` routing + noise tier** — map `codeql:js/sql-injection→sqli`, `…/ssrf→ssrf`,
   `…/path-injection→path-traversal`, etc. to real agent classes. Introduce a **`_NOISE_CLASSES`** set
   (`log-injection`, `clear-text-logging`, `unknown`-without-CWE) → a new low disposition
   `informational` (see models change) that the investigate/triage phase assigns by default *unless* a
   reachability-from-untrusted indicator is present. `informational` never enters the confirmed report or
   the FP-ladder as `raw`.
3. **General-triage as a standard phase** — document + wire the large-bucket grouping strategy and a noise
   floor as a first-class investigate variant (`{{ATTACK_CLASS}}=security-other`), invoked whenever
   `reconcile_plan` reports unrouted classes.

### Files
`sec_harness/partition.py` (`reconcile_plan`), `sec_harness/clsmap.py` (rule→class map + `_NOISE_CLASSES`),
`sec_harness/prefilter.py` (surface routed vs noise counts in the result), `SKILL.md`/`CLAUDE.md` phase step,
`agents/investigate.md` (informational disposition rule).

### Tests
`test_partition.py`: reconcile_plan adds an agent for a codeql:sqli class recon omitted; noise classes are
NOT added as investigate agents. `test_clsmap.py`: rule→class mappings; noise classification.

### Acceptance
On a coterie-backend-shaped candidate set, sqli/ssrf get a routed agent; log-injection/unknown land
`informational`, not `raw`.

---

## Cluster C — Phase-adversary gate wiring  (P1)

### Defect (O-004)
The deterministic pre-check works, but the gate record persists only opaque `claim_id`s — no claim text or
refs. The opus adversary told to "review the sent_to_adversary claims" has nothing concrete; it can only
free-form re-review. The repo-1 win happened *despite* this (the prompt says "re-derive from code"). No
claim-extraction glue exists — the orchestrator hand-builds claims.

### Direction / reasoning
The two halves of the gate must share a claim vocabulary. Make the claim a first-class object that flows
from artifact → deterministic check → adversary → applied verdict.

### Changes
1. **Persist claim content** — `build_gate_record` stores full `{id, text, refs, status, reasons}` per
   claim (not just id + status). `write_gate_record` unchanged shape otherwise.
2. **Claim extractors** — `phase_gate.claims_from_profile(profile)`,
   `claims_from_context(ctx)`, `claims_from_architecture(md, entities)`, each returning
   `[{id, text, refs}]`. Orchestrator + Go share these instead of hand-rolling.
3. **Adversary reads content** — `agents/phase-adversary.md` updated to consume `claims_in` (id+text+refs)
   from the gate record and emit a verdict row per claim id.

### Files
`sec_harness/phase_gate.py`, `agents/phase-adversary.md`, SKILL phase-gate section.

### Tests
`test_phase_gate.py`: gate record round-trips claim text+refs; extractors produce resolvable refs from a
sample profile/context/architecture.

---

## Cluster D — needs-runtime status flow

### Defect (O-010, O-021)
`needs-deployment-testing` isn't settable at investigate stage → catalog/runtime-only findings ride as weak
`raw`. `redteam.discriminate()` filters on status first, so a `verify-error`/`raw` finding (the *clearest*
needs-runtime item) never enters the plan until promoted — and nothing promotes it automatically (done by
hand on repo 1).

### Direction / reasoning
A finding that is real-but-only-provable-live must have a first-class path to the runtime plan. Two hooks:
let investigate flag runtime-dependence, and auto-promote honest `verify-error`s with an external-data
blocker.

### Changes
1. **`runtime_dependent` marker** — investigate/validate may set it (models field or a reserved
   `evidence_sources`/reachability blocker value `external-data-required`). `investigate.md`/`validate.md`
   updated: when the only thing blocking confirmation is data not in the repo, set the marker instead of
   forcing `raw`.
2. **Auto-promote step** — deterministic post-validate: a `verify-error` finding whose reachability blocker
   is `external-data-required` (or carries `runtime_dependent`) → `needs-deployment-testing`. Add
   `campaign.promote_runtime_dependent(ws)` and a SKILL step.
3. Confirm `redteam.discriminate()` already accepts `needs-deployment-testing` (it does per redteam.md) —
   add a test locking it.

### Files
`sec_harness/models.py` (marker field if chosen), `sec_harness/campaign.py` (promote step),
`agents/investigate.md`, `agents/validate.md`, `agents/redteam.md`, SKILL.

### Tests
`test_campaign.py`: a verify-error+external-data finding promotes to needs-deployment-testing and then
appears in the rendered plan.

---

## Cluster E — Coverage accounting

### Defect (O-007, O-033)
Prefilter returns "N backends ran, 0 failed" identically whether it covered 100% or 42% of the code (Liquid
uncovered; business-logic 0-candidate). "Clean" has no denominator. And investigate MUST run even at 0 SAST
candidates or a business-logic repo reads as clean (signal inversion).

### Direction / reasoning
Every "clean" or "N findings" statement must carry *what fraction of the code was actually analyzed, and how
(dataflow vs pattern-only vs none)*. Coverage is data, not prose.

### Changes
1. **`coverage` block from prefilter** — `run_prefilter` result gains `coverage`: per language,
   `{files, bytes, tier: "dataflow"|"pattern-only"|"none"}` derived from which backends applied to which
   language (codeql langs = dataflow; semgrep-only = pattern-only; Liquid/unsupported = none).
2. **Report "Coverage & limitations" section** — `report.py` renders it; the summary line reads "N
   confirmed over X% of code by dataflow; Liquid (58%) uncovered."
3. **Investigate-runs-at-0-candidates invariant** — a hard, tested driver rule + SKILL emphasis:
   `agents_to_spawn` non-empty ⇒ investigate runs regardless of candidate count. Add a guard helper
   `partition.must_investigate(profile) -> bool`.

### Files
`sec_harness/prefilter.py`, `sec_harness/report.py`, `sec_harness/partition.py`, SKILL.

### Tests
`test_prefilter.py`: coverage block present + tiers correct for a mixed js/liquid tree. `test_report.py`:
coverage section renders. `test_partition.py`: must_investigate true at 0 candidates when classes exist.

---

## Cluster F — Robustness

### Defects
- **T7 (O-029):** `calibrate` KeyError-crashes on one malformed CVSS vector (`C:M`), zeroing risk for ALL
  findings — no validation, no per-finding isolation.
- **T8 (O-013):** findings JSON has no atomic read-modify-write; concurrent phases can clobber.
- **T13 (O-017):** background-agent final summaries frequently don't propagate; orchestration relied on
  reading disk state instead.
- **T15 (O-001):** prompts use repo-root-relative paths + `uv run from helpers`; silent empty reads if not
  injected.

### Changes
- **T7:** validate `cvss_vector` metric values at `findings_gate` (reject/repair invalid C/I/A/… values);
  `calibrate` wraps per-finding scoring in try/except → bad vector yields `risk_score=None` + a logged
  warning, never a batch crash. Add legal metric values inline to investigate/validate prompts.
- **T8:** atomic finding writes (`write_findings` → temp-file + `os.replace`); document + enforce ladder
  serialization (critic→judge→validate never concurrent on the same finding).
- **T13:** persist each agent's final return to `runs/<agent>.txt` (or standardize on always reading disk
  state) so the orchestrator never depends on the summary message.
- **T15:** add `{{HARNESS_ROOT}}` + `{{HELPERS_DIR}}` substitution tokens; orchestrator injects absolute
  paths.

### Files
`sec_harness/findings_gate.py`, `sec_harness/calibrate.py`, `sec_harness/workspace.py` (atomic write),
agent prompts, SKILL.

### Tests
`test_calibrate.py`: a malformed vector yields None for that finding, valid others still score.
`test_findings_gate.py`: invalid cvss metric rejected. `test_workspace.py`: write is atomic.

---

## Cluster G — Report / plan polish

### Defects & changes
- **T11 (O-022/023/019):** condensed report tier drops §3 Confirmation (the receipts = trust anchor) — add
  a one-line evidence/receipts row in condensed mode. Report doesn't link `redteam-plan.md` — append a
  "Manual runtime testing → redteam-plan.md (N directives)" section. `patch_diff` conflates diff vs no-fix
  prose — patch emits structured `fix_disposition` (`kind: code-fix|out-of-scope|no-fix`, `diff?`,
  `rationale`, `residual_risk`) per the existing `fix-disposition.schema.json`; verify/report branch on
  `kind` instead of git-applying prose.
- **T12 (O-020):** non-Finding leads (CI deploy-token) get a `LEAD-####` carrier
  (`status: needs-deployment-testing`, `cls: manual-review`) that flows to the redteam plan's manual
  follow-up section.
- **T14 (O-012):** every phase stamps a per-finding pass history event (`critic:viable`) so "reviewed &
  passed" is auditable and resume-safe.
- **T16 (O-000/005):** reconcile the C1/recon ordering between SKILL.md and CLAUDE.md; note gate cost.

### Files
`sec_harness/report.py`, `sec_harness/redteam.py`, `agents/patch.md`, `agents/critic.md`,
`sec_harness/context.py` (LEAD carrier), SKILL.md, CLAUDE.md.

---

## Build order & rationale

Impact × risk, cheapest-safe-first:

1. **A** (prioritization) — highest impact on the deliverable, self-contained, low risk.
2. **F/T7** (calibrate crash) — hard crash, tiny fix, unblocks trusting risk output.
3. **B** (routing/noise) — biggest signal/noise lever; introduces `informational` (models touch).
4. **C** (gate wiring) — self-contained, makes the adversary reliable.
5. **E** (coverage) — reshapes prefilter result + report; do after B settles class handling.
6. **D** (status flow) — models field + promote step; depends on E's disposition vocabulary.
7. **G** (polish) — report/plan/prompt cleanups last.

Each cluster: failing test(s) first (repo convention), then minimal implementation, then `ruff`/`ty` clean,
then commit on the working branch (`skill-audit-driver-20260731`). Models/prefilter-result changes (B, D, E)
reshape data the Go port mirrors — **decoupled from this work per owner direction**; note them for a later
golden regeneration but do not block on it.

## Status (2026-08-02 — branch close-out)

All clusters landed. Cluster F completed: **T7** (calibrate crash isolation), **T8** (atomic
`write_findings` via temp + `os.replace` in `workspace.py`), **T13** (agent-return persistence —
`workspace.record_agent_return`/`read_agent_return` → `runs/<agent>.txt`; documented in SKILL as the
disk-state-is-truth convention), **T15** (`{{HARNESS_ROOT}}`/`{{HELPERS_DIR}}` path tokens across all
agent prompts + SKILL substitution list). Cluster G **T11c** (patch `fix_disposition` schema
migration) stays deferred per `clusterG-polish.md` (current free-form `patch_diff` + verify's graceful
git-apply-failure degrade acceptably). Pre-existing, out-of-scope: the `secrets → codeguard-0-cryptography`
citation remap (that file already carries the "keys never hardcoded" guidance) fixed a broken mapping
that failed `test_citations` on `main`.

## Non-goals
No new SAST engines. No change to the read-only-source invariant. No rewrite of the agent orchestration
model (still main-agent + subagents). No speculative config.
