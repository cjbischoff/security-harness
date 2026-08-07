# sec-harness — Process Review & Pipeline Hardening (Spec A)

**Date:** 2026-08-07
**Status:** design (approved for spec write; awaiting user review before writing-plans)
**Author:** brainstorming session following the AEM 4-repo dogfooding audit
**Scope:** single-repo pipeline correctness/completeness/tunability + issue reconciliation.
**Out of scope:** multi-repo holistic correlation → **Spec B** (separate, sequential, depends on §2 here).

---

## 1. Goal & success criteria

Deliver one **process-review milestone** that makes the single-target pipeline:

1. **Correct on monorepo sub-service scans** — no path-base failures in gate / dedupe / verify /
   discovery.
2. **Honest in scoring/disposition** — every finding is either source-`confirmed` (with a mechanical
   receipt) or `needs-deployment-testing` (red-team-actionable), each carrying a real `risk_score`.
3. **Strict at the gate** — schema-type and evidence-whitelist violations FAIL, never warn-and-pass.
4. **Complete in coverage + reporting** — a scan cannot present as "clean" while an attack-surface
   class has no confirmed/NDT finding and no logged coverage-hole; `report.md` never understates a
   repo whose findings are all `needs-deployment-testing`.
5. **Tunable** — adversary depth, model tier, wave size, and token budget are config knobs, with a
   SKILL.md playbook for the judgement calls.

Plus a **reconciled issue ledger** (§5) so this work neither duplicates nor drops the existing
ISSUE-001…027 / cluster / qa-batched plans.

**Success test:** for each fix, a TDD acceptance test reproduces the *observed* failure mode from the
dogfooding run, then passes. Re-running the 4-repo audit would hit **zero** of the observed failures;
`ruff` + `ty` clean; the bench regression gate stays green.

---

## 2. Background — evidence base (observed failures)

From the 2026-08-07 dogfooding audit of four AEM repos (`aem-analytics`, `aem-event-service`,
`tanium-aem-analytics-service`, `aem-analytics-infra`). Full log:
`docs/dogfooding/2026-08-07-run-observations.md` (to be imported into this repo).

**Correctness (silent wrong result if trusted):**
- No canonical `repo_root`: `phase_gate.run_phase_checks(claims, root)`, dedupe fingerprints, and
  `verify`'s `git apply` each resolved against whatever base the caller passed. On a monorepo
  sub-service (`internal/aemeventservice`), recon emitted repo-root-relative refs while the
  architecture agent emitted service-subdir-relative refs — the orchestrator had to *guess a
  different base per phase*. Guessed wrong once → 20/26 gate claims falsely rejected (would have
  dropped the entire attack surface if applied blindly).
- `phase_gate._MD_CITATION` / `_parse_ref` did not capture `file:line:symbol` (graph node-id form)
  and dropped recon's `"file:line — prose"` evidence format → false rejects.
- `calibrate_findings` scores only `CONFIRMED` → every `needs-deployment-testing` finding had
  `risk_score=None`, so `redteam` (default `--min-risk 7`) had nothing to prioritize; hand-scored.
- `judge_verdict` (`severity-inflated`/`downgrade`) was written only as history text, never to the
  `severity` field → downstream severity→risk scoring used the un-capped value.
- `findings_gate` reported `runtime_test`/`reachability` written as a *string* (schema wants object)
  but exited 0 (warning) — a malformed load-bearing field passed the gate.
- `severity: "informational"` is rejected by the `Severity` enum (`reconcile_plan` skipped the
  finding as unparseable) yet `report.md` renders an "info" bucket.
- `deps` SCA candidates carry a valid `sca:osv:*` receipt but are never promoted to `confirmed`;
  hand-promoted + reachability-annotated.
- Same candidate (`math/rand`) routed to two investigate agents (crypto + security-other) → parallel
  write race on one finding file.
- `report.md` renders confirmed/fixed only → the solution + go-service repos (all findings NDT) read
  as near-empty; real risk hid in `redteam-plan.md`.
- `repo_slug` hashes the git *origin* URL only → two monorepo sub-services produce the identical slug
  (`go-9530ad70`); saved from collision only because `memory_root` roots each under its distinct
  subdir. Latent under `$SEC_HARNESS_HOME`.

**Coverage gap — reviewed-codebase docs were only partially read (found during this brainstorm):**
`discover_context_files(target)` globs relative to the *scan target*. Consequences:
- The two go services' **real design docs live at the monorepo root**
  (`docs/services/tanium-aem-analytics-service/{README.md,data-flow.md,async-aggregate-results.md}`,
  `docs/global-services/aem-event-service/README.md`) — **outside** the scanned `internal/<svc>`
  subdir → **never discovered or read**. A `data-flow.md` directly relevant to the threat model was
  missed.
- Discovery only matches `*.md`, so **every architecture/data-flow diagram**
  (`docs/service-story/**/*.puml` / `.svg` / `.png` in the solution repo; `docs/**/*.puml/.png` in
  infra) was **never ingested**, though `.puml` is plain text.
- In-scope narrative `.md` (solution `docs/service-story/*.md`; infra `docs/*.md`; the go subdir
  `README.md`) **were** read and adversary-checked. So: in-scope `.md` yes; off-root monorepo docs and
  all diagrams no.

**Speed:** codeql Go-DB build dominated wall-clock (~2–5 min/campaign); gate re-seed churn (~6 extra
calls/campaign) eliminated by a canonical base.

---

## 3. Design

### 3.1 Spine — the `ScanScope` abstraction (Theme 1 foundation)

**New module `sec_harness/scanscope.py`** and **new artifact `kb/scan-scope.json`** (NOT a
`CampaignState` field — that record is frozen; see §4):

```json
{
  "repo_root":  "/abs/path/to/git/toplevel",
  "scan_scope": "internal/aemeventservice",   // "." for a whole-repo scan
  "path_base":  "repo-root",                   // all refs resolve from repo_root
  "slug":       "go-internal-aemeventservice-1a2b3c4d",
  "sha":        "…",
  "doc_roots":  ["docs/services/tanium-aem-analytics-service", "internal/aemeventservice", …]
}
```

- `resolve(target) -> ScanScope`: `repo_root = git rev-parse --show-toplevel` (fallback: `target`);
  `scan_scope = target.relative_to(repo_root)`; `doc_roots` = the scan_scope + canonical monorepo
  service-doc dirs derived from the service name (see 3.2 T1).
- `write_scope(ws, scope)` / `load_scope(ws)` — persisted at `begin_pass`.
- **Resolution rule (invariant):** all path refs everywhere resolve against `repo_root`; all agents
  cite **repo-root-relative** and receive `{{REPO_ROOT}}` + `{{SCAN_SCOPE}}` tokens. `phase_gate`,
  dedupe fingerprinting, `verify` `git apply`, and `report` all take `scope.repo_root` as the base.
- Fixes at the root: monorepo path base, inconsistent finding `file` base, dedupe/verify path
  breakage, discovery scope. Also the prerequisite Spec B needs for cross-repo finding identity.

### 3.2 Theme work-packages (each is tests-first)

**T1 — Path / identity model**
- `scanscope.py` + `kb/scan-scope.json` (3.1).
- `repo_slug` (`repo_memory.py:67`): identity = `origin_url + "#" + scan_scope` so two subdirs of one
  monorepo differ; standalone repos unchanged (scan_scope=".").  ⚠️ signature/back-compat: keep the
  existing positional `target` arg; add scope internally via `resolve`.
- **Discovery scope fix** (`context.py:discover_context_files`): accept `(repo_root, scan_scope)`;
  glob from `repo_root`; additionally include canonical monorepo service-doc dirs
  (`docs/services/<svc>`, `docs/global-services/<svc>` where `<svc>` derives from `scan_scope`
  basename); ingest `.puml`/`.dot` (plain-text diagrams) as context; record `.png`/`.svg` diagrams as
  **coverage items** (logged, not silently skipped). Cap preserved.
- `phase_gate.claims_from_markdown` / `_MD_CITATION` / `_parse_ref`: capture backtick-wrapped refs and
  the `file:line:symbol` node-id form; resolve against `repo_root`.
- `Finding.file` (frozen field, no schema change): documented + enforced as repo-root-relative; a
  normalizer stamps it from `scope` at write time.

**T2 — Scoring / disposition correctness**
- `calibrate_findings` (`calibrate.py`): also score `needs-deployment-testing` findings
  (severity-floor via `_severity_floor`); reconcile with the existing clusterA `_derived_score` /
  `_precondition_cap(list)` design and the planned `promote_runtime_dependent` auto-call (ISSUE-027 /
  F2) so promotion→scoring is one pass.
- `judge_verdict` → `severity`: apply the judge's `severity-inflated`/`downgrade` verdict to the
  `severity` field (or have `calibrate` read `judge_verdict` and cap), so the cap is not cosmetic.
- Add `Severity.INFO = "info"` (contract change — §4); wire `_SEVERITY_FLOOR["info"]=1` (already
  present in clusterA snippet) and report bucket.
- Deterministic `deps → confirmed` promotion with a **reachability heuristic**: SCA finding with an
  `sca:osv:*` receipt is confirmed-present; if the package is lockfile-only / a devDependency /
  used only in a build stage → severity `low`, `reachability.reachable=false`, annotated. New code in
  `partition.py` or `campaign.py` (no prior art — greenfield).

**T3 — Schema / gate strictness** (`findings_gate.py`)
- Schema-type violations (e.g. `runtime_test`/`reachability` not object|null) → **exit non-zero**
  (define/confirm the hard-fail exit code used elsewhere in the gate). Add JSON-schema (or dataclass)
  definitions for `runtime_test` + `reachability` so the type is checkable.
- Evidence-whitelist gate: a finding at `confirmed`/`fixed` must have ≥1 `evidence_sources` entry that
  `evidence.is_tool_receipt()` accepts; reject pseudo-receipts (`Read:*`, `llm-claimed:*`-only).
  Reuse `evidence.is_tool_receipt` (already imported in `report.py`).
- Partition routing is a **partition, not overlapping sets**: build a `class → single agent` map so a
  candidate is dispatched once (fixes the double-dispatch write race, ISSUE-017 sibling). Dedupe
  `agents_to_spawn` before spawn.

**T4 — Reporting + methodology**
- **Populate the coverage-ledger** (`coverage_ledger.py` validator + schema exist; nothing writes
  it): derive `surfaces[]` from `profile.attack_surface` × finding status — a non-`deps` class with no
  `CONFIRMED`/`NEEDS_DEPLOYMENT_TESTING` finding and no logged coverage-hole ⇒ `disposition:
  needs_follow_up` ⇒ `validate_coverage_ledger` blocks `completeness=="complete"`. Call
  `validate_coverage_ledger` at report time so "clean" is machine-enforced. Respect the `deps`
  exclusion in `coverage_guide.coverage_complete`.
- `report.py`: confirm the NDT section renders (already implemented at `report.py:152-168/208-247` —
  add a test); add the coverage-completeness section; include NDT findings in `findings.json` (+
  SARIF) so downstream consumers see them (currently `findings.json` writes only `_REPORTABLE`).
- **Methodology knobs** on `ScanProfile` (non-frozen) — a new `scan_options` dict (or documented
  `budget_hint` keys): `adversary_depth` (`full` | `gate-by-exception`), `model_tier_map`
  (phase→tier), `wave_k` / `max_waves` (already `discovery_ledger` constants `DEFAULT_K=2` /
  `DEFAULT_MAX_WAVES=5` — expose as overrides), `token_budget`. Read by the orchestrator; validated in
  `validate_profile` (hand-written, not jsonschema). Update `references/scan-profile.schema.json`.
- **SKILL.md playbook** (prose, governs orchestrator judgement): when `gate-by-exception` is legal (it
  filters *what enters* the FP ladder, never bypasses the tool-receipt confirm bar); when to author
  KB from adversary-validated context; model-tier table. **Family-diversity stays a hard invariant,
  not a knob** (SKILL.md §18).

### 3.3 What we deliberately reuse (from the digests)
- `coverage_ledger.py` schema/validator + `coverage_guide.coverage_complete` + `tuning.gap_report`
  (wire, don't rebuild).
- `discovery_ledger` `k`/`max_waves` knobs.
- `cost.py` budget accounting in `CampaignState.budget`.
- `promote_runtime_dependent` (planned, D/F2), `_derived_score`/`_precondition_cap` (clusterA),
  `FindingStatus.INFORMATIONAL` (clusterB / A6).

---

## 4. Frozen-contract coordination

`helpers/sec_harness/models.py` (`Finding`, `CampaignState`, enums) and `evidence.py` (`_MECHANICAL`
whitelist) are mirrored byte-for-byte by the Go port (`go/internal/model/testdata`, `TestParity`).
**Rule for Spec A:**
- Prefer `kb/` artifacts over model fields (scan-scope, coverage) to avoid contract churn.
- The unavoidable contract changes — `Severity.INFO`; any evidence-whitelist adjustment — batch into
  **one "contract-change" work-package**, land it in a **separate commit**, and **flag the Go
  terminal**. Regenerating goldens (`python3 go/bench/gen_golden.py`) writes under `go/` — **out of my
  ownership**; it is an explicit handoff step, not done autonomously.
- No new `FindingStatus` variant (would force a golden regen for a report-layer concern — keep
  code-settled at the report layer per ISSUE-013/019).

---

## 5. Issue reconciliation ledger

Legend: **fixed** (already committed) · **planned** (existing task owns it; Spec A executes/absorbs) ·
**new** (Spec A greenfield).

| Item | Status | Owner / WP |
|------|--------|-----------|
| Canonical `repo_root` / `scan_scope` state | **new** | T1 (§3.1) |
| Discovery scope off repo-root + monorepo service docs + `.puml` diagrams | **new** | T1 |
| `repo_slug` monorepo-subdir collision | **new** | T1 |
| `claims_from_markdown` backtick / `file:line:symbol` | **new** | T1 |
| Finding `file` base consistency | **new** | T1 |
| calibrate scores `needs-deployment-testing` | **new** | T2 (reconcile w/ D/F2) |
| `judge_verdict` → `severity` write-back | **new** | T2 |
| `Severity.INFO` enum | **planned** (A6/ISSUE-014) | T2 + §4 |
| deps→confirmed + reachability heuristic | **new** | T2 |
| gate hard-fail on schema-type violation | **new** (GSD-listed, no task) | T3 |
| evidence-whitelist gate (reject `Read:*`) | **new** | T3 |
| partition dedup / double-dispatch race | **new** (sibling ISSUE-017) | T3 |
| coverage-ledger population + report-time enforce | **new** (validator exists) | T4 |
| report.md NDT section | **fixed** (verify + test) | T4 |
| NDT in findings.json / SARIF | **new** | T4 |
| methodology knobs + playbook | **new** | T4 |
| `promote_runtime_dependent` auto-call | **planned** (ISSUE-027/F2) | absorbed T2 |
| judge/validate serialize per-finding | **planned** (ISSUE-017/F6) | absorbed T3 |
| dedupe distinct-dataflow / cross-class | **planned** (ISSUE-016/018, D1/D2) | reference; defer unless cheap |
| CodeQL `verified-static` (verify re-runs semgrep only) | **planned** (ISSUE-021/F1) | reference; defer |
| crypto_policy CBC/bare-hash gaps | **planned** (ISSUE-026/F4) | reference; defer |
| multi-hop caller resolution | **deferred** (ISSUE-012, architectural) | out of scope |
| graph O(n²), `Workspace('<str>')`, malformed-finding skip, OUTPUT_WRITE_FALLBACK | **fixed** | — |

The remaining planned A1–A9 / B1 / C1 / E1–E3 prompt/coverage tasks are pulled under Spec A's
execution umbrella where they touch the four themes; unrelated ones stay in their own plans.

---

## 6. Testing

TDD, reusing `tests/test_contracts.py` + `tests/test_wiring.py` patterns. One failing test per
observed failure mode first:
- monorepo sub-service: gate/dedupe/verify resolve against `repo_root` (no false rejects).
- calibrate assigns `risk_score` to an NDT finding.
- gate exits non-zero on a string `runtime_test`; rejects a `Read:*`-only confirmed finding.
- judge downgrade lands in `severity`.
- discovery finds a monorepo-root service doc + ingests a `.puml`.
- coverage-ledger blocks `complete` while a class is uncovered.
- `repo_slug` differs for two subdirs of one origin.
Then minimal fix → green → `ruff check` + `ty check` clean → bench regression gate green.

---

## 7. Rollout / git

- Branch `spec/process-review-hardening-20260807` off `main` in `/Users/christopher/Tools/security-harness`.
- Stage **only** explicit `skills/sec-harness/**` paths; never `git add -A` (the repo has a parallel
  `go/` workstream I do not touch). `git status` must show only skill paths before commit.
- Contract-change work-package = separate commit + Go-terminal handoff (§4).
- Spec + plan under `skills/sec-harness/docs/plans/`. Personal remote (`cjbischoff/security-harness`)
  → no GPG signing, no AI attribution.

---

## 8. Non-goals / YAGNI

- **Spec B** (multi-repo holistic correlation: aggregator agents, unified architecture / threat-model
  / red-team / single report, report location) — separate spec, depends on §3.1.
- No diagram OCR/rendering — ingest `.puml`/`.dot` text; record image diagrams as coverage only.
- No new `FindingStatus` variant.
- Multi-hop caller resolution (ISSUE-012) stays deferred.
- Deferred-but-referenced planned tasks (dedupe D1/D2, verify F1, crypto_policy F4) only if they fall
  out cheaply from a theme; otherwise left to their own plans.
