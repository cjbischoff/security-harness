---
name: sec-harness
description: Self-contained agentic security-audit harness. Runs bundled SAST, normalizes findings, and emits SARIF + Markdown reports. Use for security audits and vulnerability scans of a codebase. This is the deterministic core; multi-agent investigation and remediation phases are added in later increments.
---

# sec-harness

A self-contained security-audit harness. It calls binary tools directly (no other
skills/plugins) and never executes the scanned code.

## Principles

Four rules govern every phase:

1. **Adversarial-review all things.** Every phase that produces findings *or analysis/context a
   later phase consumes* is battle-tested by an independent adversary before its output is
   handed forward. No phase trusts another phase's output un-challenged. Findings use the FP
   ladder (critic + adversarial-validate); analysis/context phases use the **phase adversary
   gate** (below).
2. **Create accurate context.** Context — repo docs, prior scans, recon, architecture, threat
   model — is verified against code and battle-tested before it drives anything. Inaccurate
   context is a defect caught early, never propagated.
3. **Signal over noise.** Deterministic-first gating, tool-receipt-only confirmation, and a
   high-confidence bar for the runtime plan keep false positives out of what a human acts on.
4. **Thoroughly review a codebase.** Coverage is pursued until a phase can defend it to its
   adversary; gaps are logged, never silently dropped.

## Phase adversary gates

The FP ladder already battle-tests investigate findings. The EARLIER analysis/context phases —
recon, architecture, threat-model, C1 context — each end with a reusable **phase gate** so their
output is trusted only after an independent challenge:

```
phase output → deterministic pre-check (sec_harness.phase_gate.run_phase_checks)
                 cited code ref does not resolve / malformed → REJECT (no agent), log reason
                 resolves / can't-settle → independent adversary (agents/phase-adversary.md, opus,
                                            DIFFERENT family, fresh context)
               only battle-tested claims flow forward; write kb/gates/<phase>.json
```

Deterministic-first: build claims as `{"id","refs":[file or file:line,...]}` and run
`run_phase_checks(claims, <T>)`; hard-unresolvable refs are rejected with no agent. Then spawn
`agents/phase-adversary.md` (`{{PHASE}}` = recon/architecture/threat-model/context) on the
survivors; apply its INVALIDATED/WEAKENED verdicts back to the phase artifact and record them
with `build_gate_record` / `write_gate_record`. Same independence guard as `validate.md`: opus,
different family than the sonnet producer.

## Deterministic scan (current capability)

From the harness helpers directory:

```bash
cd skills/sec-harness/helpers
uv run python -m sec_harness.cli scan \
  --target <path-to-code> \
  --workspace <path-to-output-workspace> \
  --config rules/smoke.yaml \
  --sha "$(git -C <path-to-code> rev-parse HEAD)"
```

Outputs, under the workspace directory:
- `findings/F-*.json` — one file per normalized finding (the contract for later phases).
- `report.sarif` — SARIF 2.1.0.
- `report.md` — human-readable report.
- `state.json` — campaign state (pass number, pinned SHA).

## Running a full audit

One audit pass, in order. The main agent drives this; `<T>` = target repo,
`<WS>` = workspace dir, `<sha>` = `git -C <T> rev-parse HEAD`, `<rules>` = a local
semgrep ruleset. Deterministic steps run via `uv run` from `<HELPERS_DIR>` (the
absolute path to `skills/sec-harness/helpers`); agent steps spawn a subagent with the
named prompt (tokens substituted). Prompts use path tokens, never repo-root-relative
paths, so a subagent reads the right file regardless of its CWD — substitute **all** of
these before spawning: `{{TARGET}}`, `{{WORKSPACE}}`, `{{ATTACK_CLASS}}`, `{{PHASE}}`,
`{{ROUND}}`, the two path anchors `{{HARNESS_ROOT}}` (absolute path to
`skills/sec-harness/`) and `{{HELPERS_DIR}}` (absolute path to
`skills/sec-harness/helpers`), and the two scope anchors `{{REPO_ROOT}}` (absolute
git top-level of the scanned repo, read from `kb/scan-scope.json`) and `{{SCAN_SCOPE}}`
(the audit target path relative to `{{REPO_ROOT}}`, also from `kb/scan-scope.json`).
All agents cite paths **repo-root-relative**; all gates/dedupe/verify resolve against
`{{REPO_ROOT}}` (read from `kb/scan-scope.json`). Record each phase with `record_stage(<WS>, "<phase>")` so
passes advance. Persist each agent's final return with
`workspace.record_agent_return(ws, "<agent-label>", <text>)` (→ `runs/<agent>.txt`) and
read it back with `read_agent_return` — never depend on a subagent's summary message
propagating; disk state is the source of truth. **Subagent Write-tool guard:** some hosts
hard-block a subagent's Write tool on `findings`/`report`/`summary`-like paths; agent
prompts carry the `OUTPUT_WRITE_FALLBACK` rule (write the KB/findings artifact via a
`python3 shutil.copy` from a temp file instead), so a blocked Write never silently loses a
finding. When dispatching, keep that fallback in the agent's instructions.

0. **Preflight** — `python -m sec_harness.preflight`; run any printed install/vendor commands before scanning (missing backends are skipped + logged). The report lists which **CodeQL query packs** are installed — the `codeql` binary being present does NOT mean the per-language packs exist, and a missing pack silently drops all of that language's dataflow coverage. If a language you will scan is not listed, run `codeql pack download codeql/<lang>-queries` first. CodeQL runs only on a trusted config (`codeql_config_trusted`); unsupported or untrusted configs are skipped and logged in the prefilter `failed` list.
1. **Begin pass** — `from sec_harness.state import begin_pass; begin_pass(<WS>, <sha>)` (pins the SHA; increments on repeat passes). Note the import path: `begin_pass` lives in `sec_harness.state`; `record_stage`/`pass_report` live in `sec_harness.campaign`.
C1. **Context-ingest** (sonnet) — `agents/context-ingest.md` → `kb/context.json`; `agents/context-adversary.md` (opus) pressure-checks it. Runs here, BEFORE recon, so its leads can feed recon's `attack_surface`. See **Context ingestion (C1/C2)** below.
T1. **Tier-1 substrate** (no LLM) — `python -m sec_harness.graph build --target <T> --workspace <WS> --sha <sha>`; structural_index + a regex call-edge heuristic + osv/secrets/crypto facts → `kb/graph.json` v1, consumed by recon, architecture, and threat-model.
2. **Recon** (sonnet) — `agents/recon.md` → `kb/scan-profile.json`. Validate with `load_profile`. **→ phase gate** (`agents/phase-adversary.md`, opus).
3. **Architecture** (sonnet) — `agents/architecture.md` → `kb/architecture.md` + `kb/entities/`. **→ phase gate**.
4. **Threat model** (sonnet) — `agents/threat-model.md` → `kb/THREAT_MODEL.md` (hunt list). **→ phase gate**.
5. **Prefilter** (no LLM) — `from sec_harness.prefilter import run_prefilter; run_prefilter(ws, target, profile)` (args: `Workspace`, target path, the `ScanProfile` from recon — NOT the raw `sast_plan` dict). Backends run concurrently (one unit per semgrep ruleset / codeql language); results are merged deterministically (sorted, `C-####` ids) so serial and concurrent runs are byte-identical. Returns `{candidates, backends_run, skipped, failed, excluded, dropped_nonsecurity, skipped_reasons}`: `skipped_reasons` maps each backend that did NOT run to a reason (`disabled`/`absent`/`untrusted`/`pack-missing`); `dropped_nonsecurity` counts non-security semgrep lint dropped by the security-only filter; `failed` lists backends that errored. **A scan is only clean if every PLANNED backend ran. STOP and surface a setup error if `backends_run` is empty OR any planned backend appears in `failed` / `skipped_reasons` (e.g. `codeql: pack-missing` = a missing query pack → zero dataflow for that language). A partial scan (semgrep ran, codeql failed) is a coverage hole, not "no findings" — do NOT report it as clean.** Then `demote_noise(ws)` (moves log-injection/clear-text-logging/unknown candidates to `informational`), `agents = reconcile_plan(ws, profile.agents_to_spawn)` (routes real-security classes recon omitted), and `agents = merge_custom_check_classes(agents, discover_custom_checks(target))` (from `sec_harness.custom_checks`; adds any in-repo `.sec-harness/checks/` bundles the target declares). Spawn investigate agents over the reconciled `agents`; for any class that is a custom-check id, append `custom_check_instructions(check)` to the standard `agents/investigate.md` prompt after the shared `prompt-constants.md` blocks, per its check's own bundle. The general-triage `security-other` agent handles any residual unrouted classes.
6. **Investigate** (sonnet, parallel over `scan-profile.agents_to_spawn`) — `agents/investigate.md` per class → `raw`/`rejected`/new `A-####`.
7. **Dedupe** (no LLM) — `python -m sec_harness.dedupe --workspace <WS>`.
8. **Critic** (sonnet) — `agents/critic.md` (production viability) → rejects non-shipping.
9. **Adversarial validate** (opus, DIFFERENT family) — `agents/validate.md` → `confirmed`/`rejected`.
10. **Calibrate** (no LLM) — `python -m sec_harness.calibrate --workspace <WS>` → `risk_score`.
11. **Patch** (opus) — `agents/patch.md` → `patch_diff` on confirmed findings.
12. **Verify** (no LLM) — `python -m sec_harness.verify --workspace <WS> --target <T> --config <rules>` → `fixed`/`verified-static`.
13. **Gate** (no LLM) — `python -m sec_harness.findings_gate --workspace <WS>`.
13.5 **Red Team** (sonnet + opus adversary) — `agents/redteam.md` sets `runtime_disposition` +
    `runtime_test` on confirmed findings; `agents/redteam-adversary.md` pressure-checks the plan;
    `python -m sec_harness.redteam --workspace <WS>` renders `redteam-plan.md`. See **Phase 5.5**.
14. **Report** (no LLM) — `python -m sec_harness.report --workspace <WS>` → final `report.sarif` + `report.md` (confirmed/fixed only, with risk + verification); points at `redteam-plan.md`. Report auto-builds `kb/coverage-ledger.json` from `attack_surface × finding status` when absent (`coverage_ledger.build_coverage_ledger`); a class with no confirmed/NDT finding blocks `completeness==complete`. `findings.json` now carries confirmed/fixed **and** needs-deployment-testing findings (distinguished by `status`).

For repeat passes see **Phase 6** (incremental scoping + carry-forward). The per-phase
sections below detail each step.

**Cost-recording convention:** after each subagent completes, the orchestrator records its token
usage with `cost.record_agent(state, <phase>, <model>, <tokens>)` and `save_state`; the final
report renders measured per-phase token totals ("Token spend by phase"). USD is an opt-in
estimate (`cost.estimate_cost_usd`), never shown as a measured figure.

## Process methodology (knobs + playbook)

Four `scan_options` knobs let the orchestrator tune cost, coverage, and fan-out without
weakening the FP ladder. Two of them carry hard invariants that are not knobs.

### `scan_options.adversary_depth`

Controls how eagerly the harness spawns the opus phase-adversary for each analysis phase
(recon / architecture / threat-model / C1 context).

- **`full`** (default): every analysis phase runs its opus `phase-adversary` after the
  deterministic `phase_gate`. This is the safe, highest-confidence mode and the right
  choice for audits where you cannot pre-validate that prior adversarial output covers
  the same scope.
- **`gate-by-exception`**: the deterministic `phase_gate` always runs. The opus
  phase-adversary is spawned only when a phase adds material NEW claims beyond context
  that has already been adversarially validated — for example, when the context-adversary's
  enumeration of components and trust boundaries already covers the architecture phase's
  scope, spawning a second full opus adversary is redundant.

**HARD rule:** `gate-by-exception` filters what enters the FP ladder — it controls which
phase-adversary invocations fire — but it **never** lets a finding reach `confirmed` without
a mechanical tool receipt. The finding-side FP ladder (critic → judge → adversarial-validate)
always runs at full strength regardless of `adversary_depth`.

Authoring KB artifacts (e.g. `architecture.md`, `THREAT_MODEL.md`) directly from a verified
adversary-context output is permitted **only under `gate-by-exception`** — when the opus
context-adversary has already enumerated components and trust-boundaries with cited `file:line`
evidence, the orchestrator may author those artifacts from that verified output instead of
spawning fresh agents. Every finding produced from that KB still passes the full FP ladder.

### `scan_options.model_tier_map`

Phase-to-tier overrides. The default table is:

| Phase(s) | Tier |
|---|---|
| recon, architecture, threat-model, context-ingest, investigate, critic, redteam | sonnet |
| adversarial-validate, patch, phase-adversary, redteam-adversary, context-adversary | opus |
| pure-transcription implementer work | haiku (cheap tier) |

**HARD invariant — model-family diversity:** the adversarial validator must be a different
and stronger model family than the sonnet producer. This is an invariant, not a knob: a
single-model-family environment must degrade to a fresh-context validator (a new context
window with no memory of the finding-production run) and LOG it explicitly. Never let the
finder be the sole confirmer.

If `model_tier_map` overrides a tier in a way that would place finder and validator in the
same family, the harness must detect it, fall back to the fresh-context validator, and record
the degradation in `state.json`.

### `scan_options.wave_k` / `max_waves`

Override the discovery-ledger saturation parameters passed to `new_ledger(...)` in the
investigate phase. Defaults: `K=2` (consecutive waves with no new fingerprints → saturated),
`max_waves=5` (hard cap). Increase `wave_k` to require more consecutive flat waves before
declaring saturation (raises recall at the cost of more investigate round-trips); decrease
`max_waves` to enforce a tighter token ceiling on discovery. The adversarial coverage gate
still runs after the loop; these knobs tune the saturation floor, not the gate itself.

### `scan_options.token_budget`

Soft per-scan output-token target. The orchestrator uses this as a scaling signal: a tighter
budget narrows the investigate fan-out (fewer parallel wave agents per round-trip) and may
skip optional tuning rounds; a looser budget widens fan-out and enables the adaptive
tool-tuning loop (Phase 0.5). The budget is a steering heuristic, not a hard abort — a
finding already in flight is never dropped mid-run to hit the target. Record measured token
spend per phase with `cost.record_agent` so the next run can calibrate.

## Phase 0–1: Knowledge Base build + threat model (agentic)

Run BEFORE the deterministic scan so the profile can guide later phases. The main
agent orchestrates three subagents sequentially via the Agent tool, each given the
corresponding prompt template with `{{TARGET}}`/`{{WORKSPACE}}` substituted. All
are READ-ONLY over the target and call only binary tools (`rg`, file reads).

1. **Recon** (model: sonnet) — prompt `agents/recon.md`. Surveys the repo, writes
   `{{WORKSPACE}}/kb/scan-profile.json`. Validate it afterward:
   `uv run python -c "from sec_harness.profile import load_profile; load_profile('{{WORKSPACE}}/kb/scan-profile.json')"` (raises on invalid).
2. **Architecture** (model: sonnet) — prompt `agents/architecture.md`. Reads the
   profile + repo, writes `kb/architecture.md` and `kb/entities/*.md`.
3. **Threat model** (model: sonnet) — prompt `agents/threat-model.md`. Reads the KB
   only, writes `kb/THREAT_MODEL.md` (trust boundaries, attacker profiles,
   prioritized hunt list).

**Phase completion + crash recovery:** a phase is done only when ALL its outputs
exist AND `record_stage` ran — never infer completion from one file's presence
(an agent can crash after writing `architecture.md` but before `kb/entities/*`).
If an agentic phase dies (e.g. transient 429/529), resume the same agent by its
id (context intact) or re-run it; the deterministic phases are idempotent. Verify
outputs before advancing.

The prioritized hunt list + `scan-profile.json` (`attack_surface`/`agents_to_spawn`)
drive the investigation phase (later increment). `sast_plan` will drive SAST backend
selection when the deterministic scan is wired to consume the profile (later increment).

## Phase 0.5: Adaptive tool tuning (optional, ratcheted loop)

Optional refinement loop; off by default for a quick scan, on for a thorough audit.
Runs AFTER Phase 0–1 (recon produces baseline `sast_plan`) and BEFORE the deterministic
scan (Phase 2). If skipped, proceeds directly to Phase 2–3 with the recon profile unchanged.

**Round 0 (baseline):**
Run the full pipeline (prefilter → investigate → FP ladder with recon's `sast_plan`) →
capture `best` = confirmed findings set. Snapshot the findings:
`snapshot0 = signal_snapshot(findings)`. Record the baseline:
`TuningLog(ws).record(0, {"baseline": true}, snapshot0, "baseline")`.

**Round k (k ∈ 1..≤3):**
1. Compute gap: `gap = gap_report(findings, profile.attack_surface)` — partitions
   the attack surface into classes that do vs. don't yet carry a tool receipt
   (coverage-based, regardless of confirmation status); the uncovered set is the
   tuner's worklist.
2. Spawn `agents/tune-config.md` (model: sonnet) with `{{ROUND}}=k`, current `sast_plan`,
   `snapshot`, and `gap` → writes `kb/tuning/round_k/` (generated rules + `exclusions.json`
   + updated `sast_plan`).
3. Merge the round's config into the workspace: add its rule dir to
   `sast_plan.semgrep.rulesets`; merge its `exclusions.json` into `kb/exclusions.json`.
4. Run the **full pipeline** again with merged config → `candidate` confirmed set +
   `snapshot_k`.
5. `is_improvement(best, candidate)` (ratchet: lose-none + new-tool-receipt)?
   - **Accept**: `best = candidate`; persist merged config to `kb/scan-profile.json`
     and keep round rules; `record(k, diff, snapshot_k, "accepted")`.
   - **Revert**: restore prior `sast_plan` and `kb/exclusions.json`; discard round
     rules; `record(k, diff, snapshot_k, "reverted")`.

**Stop condition:**
2 consecutive `reverted` rounds, OR round `k == 3`, OR token budget exhausted.
Accepted config persists in the KB for reuse by later multi-pass runs (re-tune only
on material code change).

**Cost note:**
Each round re-runs the full agentic pipeline; the round cap (3) + strict ratchet
bound the spend. Confirmed-delta conflates config effect with FP-ladder non-determinism
— the ratchet (lose-none + new-tool-receipt) is the guard; every round's config diff
+ snapshot is in `kb/tuning_log.jsonl`.

## Phase 2–3: Prefilter + investigation (agentic)

Run AFTER the KB build. Prerequisites in the workspace: `kb/scan-profile.json`,
`kb/THREAT_MODEL.md`, and candidate findings from the deterministic prefilter.

1. **Prefilter** (no LLM): run the deterministic scan to produce candidate
   findings (Plan 1):
   `uv run python -m sec_harness.cli scan --target <T> --workspace <WS> --config <rules> --sha <sha>`
2. **Investigate** (model: sonnet, PARALLEL): partition candidates first —
   `partition_candidates_by_class(ws)` (from `sec_harness.partition`) groups them
   by `cls`. Investigate runs whenever `must_investigate(profile)` is true (any
   planned class) — even at 0 SAST candidates. A 0-candidate business-logic repo
   is a coverage story, not a clean bill (O-007). Then dispatch the investigate
   subagents **in ONE message** — one per
   class in `scan-profile.json` `agents_to_spawn` (after merging in any custom-check
   classes via `sec_harness.custom_checks.discover_custom_checks(target)` +
   `merge_custom_check_classes`), each with `agents/investigate.md`
   (substituting `{{ATTACK_CLASS}}`, `{{TARGET}}`, `{{WORKSPACE}}`) and handed its
   partition — so they run concurrently. When `{{ATTACK_CLASS}}` is a custom-check id,
   append that check's `custom_check_instructions(check)` markdown to the assembled
   prompt after the shared `prompt-constants.md` blocks (`ANTI_MANIPULATION`,
   `TOOL_TRUST`, `SEVERITY_PRECONDITION`, etc.) so it gets the same trust envelope as
   every built-in class. A custom-check candidate goes through the full existing gate
   ladder — dedupe, critic → judge → validate → trace, calibrate — exactly like any
   other finding; there is no lighter-weight path for org-authored checks.
   **Do not orphan candidates.** The classifier produces classes beyond
   `agents_to_spawn` — `security-other`/`unknown` for vendored rules that carry no
   `cls`/CWE, and these can hold high-value hits (command-exec, weak-crypto).
   Call `unrouted_candidate_classes(ws, agents_to_spawn)` (from `sec_harness.partition`);
   if it returns anything, LOG the counts and spawn a general-triage investigate
   agent (`{{ATTACK_CLASS}}=security-other`, handed those candidates) so nothing is
   silently dropped. The rule-id router in `clsmap` now maps the common vendored
   `lang.security.*` rules to their real class, but the safety net still catches
   the rest.
   **One candidate, one agent.** Each candidate's `cls` routes it to exactly one investigate agent (`partition_candidates_by_class`). Never hand the same candidate/file to two class agents in parallel — concurrent writers to one finding file race (last-writer-wins). If a candidate looks cross-class, pick the primary class; the others hunt by shape.
   **Robustness (fan-out under provider load):** the one-message fan-out maximizes
   simultaneous API load; a transient 429/529 can wipe the whole batch, and agents
   write findings only when they finish, so mid-run crashes lose the batch's work.
   Keep concurrency bounded (dispatch in waves of ~3–4 on a flaky API rather than
   all classes at once), retry a failed agent with backoff (or resume it via its
   agent id — its context is intact), and re-dispatch is safe because completed
   candidates already carry a terminal status (skip classes whose candidates are
   all non-`candidate`). The same applies to the critic/validate/patch fan-outs. Each triages its class's candidates + the
   threat model's hunt-list rows for that class, and writes `raw`/`rejected`/new
   findings. Findings use class-prefixed ids (e.g. `SQLI-0001`), so parallel agents
   never contend on id allocation. The shared KB is prompt-cacheable across them. **All agents import `references/prompt-constants.md` and wrap untrusted
   repo text in the trust envelope.** Findings use class-prefixed ids (e.g., `SQLI-0001`) and
   ground evidence in tool receipts via `evidence_sources` in colon form (e.g., `semgrep:<rule>`,
   `codeql:dataflow`, `ast-grep:sink`, `structural-index:callers`) — these are the mechanical
   sources `evidence.is_tool_receipt` recognizes; LLM assertions are `llm-claimed:*`.
   Gate −1 (sanity/hallucination) pre-gates findings before hard gates 0–3 evaluate exploitability,
   patch viability, and false-positive likelihood.
   On pass N>1, fill `{{FP_FEEDBACK}}` with `fp_feedback.render_fp_feedback(ws)` output
   (empty string on pass 1 or when there are no prior rejections).
   Investigate runs as a bounded saturation loop: after each discovery wave, fold the
   wave's candidate fingerprints into `kb/discovery-ledger.json`
   (`discovery_ledger.record_wave`) and stop when `terminal_reason` is set — `saturated`
   (K=2 consecutive waves added no new fingerprints) or `capped` (max_waves=5). The
   adversarial coverage gate still runs after the loop; saturation is a recall floor, not
   a replacement for it.
3. **Gate** (no LLM): validate all findings conform:
   `uv run python -m sec_harness.findings_gate --workspace <WS>` (exit 1 on any invalid finding).

Confirmed (`raw`) findings flow to the FP-reduction ladder (Plan 4).
The structural index (`python -m sec_harness.structural_index ...`) is the agents'
navigation aid; it uses `rg` only and degrades to search when heuristics don't apply.
tree-sitter is an optional future upgrade to structural-index precision; not required.

## Phase 4: False-positive reduction ladder

Runs on `raw` findings from investigation, cheap→expensive. A finding must pass
every step to reach `confirmed` with a risk score. Count-invariant validation ensures
the total finding count is tracked at each rung; findings require file:line evidence
to advance.

1. **Dedupe** (no LLM): `uv run python -m sec_harness.dedupe --workspace <WS>` —
   merges exact `(file, line, cls)` collisions; losers become `duplicate`.
2. **Critic** (model: sonnet, PARALLEL): critic is per-finding independent —
   dispatch critic subagents for the `raw` findings **in one message** (one per
   finding, or per small batch) with `agents/critic.md` (`{{TARGET}}`/`{{WORKSPACE}}`
   substituted) rather than one-at-a-time. Rejects `raw` findings that are not
   triggerable in a release build (debug-only, dead code, disabled assertions).
   All agents import `references/prompt-constants.md` and wrap untrusted repo text.
   On pass N>1, fill `{{FP_FEEDBACK}}` with `fp_feedback.render_fp_feedback(ws)` output
   (empty string on pass 1 or when there are no prior rejections).
3. **Judge, then adversarial validate** (model: opus for validate — MUST be a DIFFERENT
   family than the sonnet investigator; parallelism does NOT relax this guard): dispatch
   `agents/judge.md` first and wait for its writes to persist before dispatching validate —
   judge and validate must never run concurrently against the same finding file, since the
   last writer silently drops the other's field (ISSUE-017). Once judge has completed, dispatch
   validate subagents **in one message**, one per surviving `raw` finding, with
   `agents/validate.md`. Each tries to REFUTE its finding; survivors → `confirmed`,
   refuted → `rejected`. If only one model family is available, degrade to a fresh-context
   validator and log it — never let the finder be the sole confirmer. A finding with
   only `llm-claimed:*` evidence sources cannot reach `confirmed` (safety-contract:
   only tool receipts suppress the LLM's hallucination risk). `verify-error` is a
   valid terminal state (distinct from `confirmed` and `rejected`) for findings that
   fail validation infrastructure.
4. **Calibrate** (no LLM): `uv run python -m sec_harness.calibrate --workspace <WS>` —
   promotes raw findings marked `runtime_dependent` to `needs-deployment-testing` (via
   `promote_runtime_dependent`, `sec_harness.campaign`; ISSUE-027) before setting `risk_score`
   1–10 on every `confirmed` finding.
5. **Gate** (no LLM): `uv run python -m sec_harness.findings_gate --workspace <WS>`.

`confirmed` findings with `risk_score` are the harness's output. Patch generation +
static verification (Plan 5) and final report assembly (Plan 7) come next.

## Phase 5: Patch generation + static verification

Runs on `confirmed` findings from the FP ladder. No target code is executed;
patches apply to a throwaway copy only.

1. **Patch** (model: opus, PARALLEL): patches for distinct confirmed findings are
   independent — dispatch patch subagents **in one message**, one per confirmed
   finding, with `agents/patch.md` (`{{TARGET}}`/`{{WORKSPACE}}` substituted). Each
   writes a unified-diff `patch_diff` into ONLY its own finding's file, so parallel
   writers touch distinct per-id files and never collide. Read-only on the target.
2. **Validate-fix** (model: opus, personas: `security-architect` + `penetration-tester`):
   spawn a subagent with `agents/validate-fix.md` to assess patch viability and exploit
   resistance. Uses `sec_harness.scoring.score_fix` to grade each patch.
3. **Verify** (no LLM): `uv run python -m sec_harness.verify --workspace <WS>
   --target <T> --config <rules>` — for each confirmed finding with a patch, copies
   the target, applies the patch with `git apply`, re-runs the SAST on the copy, and
   compares the pre/post presence of the finding's class. Flagged pre-patch and
   gone post-patch → `status: fixed`, `verification: verified-static`. The non-waivable
   `no_new_vulnerabilities` regression gate must pass (no new findings introduced by
   the patch). Applied cleanly but the hit survives → `verification: not-fixed` (kept `confirmed`).
   Not SAST-detectable pre-patch or the patch fails to apply → `verification:
   static-only` (kept `confirmed`). The original target is never modified.
4. **Gate** (no LLM): `uv run python -m sec_harness.findings_gate --workspace <WS>`.

`fixed` findings carry a `verified-static` verification; `confirmed`/`static-only`
findings are real but unverified fixes. Final report assembly + the multi-pass
campaign supervisor are the remaining increments.

## Phase 5.5: Red Team — the static→runtime bridge

Runs on `confirmed`/`fixed` findings (plus `needs-deployment-testing` leads) after Verify+Gate,
before Report. Static analysis proves some findings outright and leaves others high-confidence-
but-not-provable-from-source (auth/session-bypass reachability, TOCTOU/races, real payload
delivery, business-logic abuse). This phase hands a human exactly which of those to test on the
running system, and how. **The harness never executes the target — it emits a plan a person
runs manually.**

0. Runtime-dependent leads are already promoted: Calibrate (Phase 4) ran
   `promote_runtime_dependent(ws)` before scoring, so raw findings marked `runtime_dependent`
   became `needs-deployment-testing` and are already eligible for the plan (O-021/ISSUE-027).
1. **Red Team** (model: sonnet): spawn `agents/redteam.md`. It sets `runtime_disposition` on
   each confirmed finding — `static-settled` (source-provable) or `needs-runtime` (needs a live
   check) — and writes a `runtime_test` block (`objective`/`preconditions`/`payloads` with
   `$SHELL_VARS`/`expected_signal`/`telemetry`) on the `needs-runtime` ones. It may also surface
   high-confidence attack *paths* across findings, each still requiring tool-receipt-grade static
   evidence to enter the plan.
2. **Red Team adversary** (model: opus, DIFFERENT family): spawn `agents/redteam-adversary.md`.
   It strips items that are actually static-settled, whose payload doesn't match the code path,
   or whose confidence isn't tool-receipt-grade. Applies verdicts (see the gate schema); record
   into `kb/gates/redteam.json`.
3. **Render** (no LLM): `python -m sec_harness.redteam --workspace <WS> [--min-risk N]` writes
   `redteam-plan.md`: prioritization table · manual test directives (payloads with shell vars) ·
   runtime-validation gaps · static-settled summary. Only findings at/above the confidence bar
   (`risk_score >= min-risk`, default 7) enter the actionable plan — signal over noise; weaker
   runtime candidates land in runtime-validation gaps, not as directives.

`redteam-plan.md` is the operator's manual-testing follow-up; the main report links to it.

## Reference-tool hardening (from audit + defending-code-reference-harness)

Cross-cutting reliability + recall additions, wired into the phases above:

- **Reachability gate (trace).** Before the red-team phase, optionally run `agents/trace.md`
  (opus) on confirmed findings: it backward-traces sink→entry, writes a `reachability`
  verdict (`{reachable, blocker, chain}`; blocker taxonomy in `sec_harness.reachability`), and
  demotes findings proven unreachable with a cited blocker. `reachability` is the primary
  static-settled-vs-needs-runtime discriminator the red-team phase reads. Recall-safe:
  unassessed ≠ unreachable.
- **Cheap adjudicator (judge).** In the FP ladder, after critic and strictly before
  adversarial-validate begins, `agents/judge.md` (no tools, token-cheap) reads only the finder +
  critic texts and sets `judge_verdict` (`uphold`/`severity-inflated`/`downgrade`) — a cheap
  inflation-catcher that never hard-rejects (no source access). Judge must complete and persist
  its write before validate starts: never dispatch judge and validate concurrently against the
  same finding file — the last writer wins and silently drops the other's field (ISSUE-017).
- **Schema-per-stage validation + in-session repair.** After any structured stage output, call
  `sec_harness.stage_validate.validate_stage(stage, obj)`; on errors, re-prompt the SAME
  subagent with `repair_prompt(...)` (quotes the exact errors, asks to re-emit only broken
  fields) and re-validate — bounded attempts. Reuses `validate_profile`/`Context.validate`/
  `validate_reachability`.
- **Fail-open parsing.** Parse agent JSON with `sec_harness.parse.extract_json` (whole → fenced
  → largest-balanced, string-aware); it returns `None` on failure so a parse miss is surfaced,
  never mistaken for "nothing found".
- **Salvage + terminal statuses.** On an investigate/patch subagent error, call
  `campaign.salvage_partial(ws, err)` to stamp findings written before the crash as `salvaged`
  (graded on resume, not re-derived). `campaign.TERMINAL_STATUSES` marks which findings resume
  must NOT re-run (non-terminal = retried).
- **Subsystem partitioning.** Recon emits `scan-profile.json` `subsystems` (parsers/protocol/
  endpoints/auth); investigate distributes attack-classes ACROSS subsystems so parallel agents
  don't converge on the same shallow code. Scale coverage by re-partitioning, not by piling
  agents on one slice.
- **Methodology (bucket A).** `SHAPE_HUNTING` + `SEVERITY_PRECONDITION` prompt-constants;
  investigators hunt by shape (not limited to their seeded class) and keep uncertain findings
  `raw` (reject only with a cited control); investigate/patch refute their own finding/fix
  first; calibrate caps risk by precondition count + flags severity inflation; validate applies
  the threat model as a kill-filter.
- **Recall + grounding loops (bucket B).**
  - **Variant hunt** — after a finding is `confirmed`, `sec_harness.variant.variant_seeds`
    turns it into sibling-search seeds; `agents/variant-hunt.md` enqueues siblings as
    `candidate`s that re-enter the gate ladder (one bug → its family).
  - **Git-history mining** — `sec_harness.githist.security_fix_commits` seeds recon with past
    security-fix patterns ("was the fix complete + applied everywhere?").
  - **Bug-chain analysis** — `python -m sec_harness.bugchain` assembles the confirmed set +
    a link prefilter; `agents/bugchain.md` traces low findings that compose into a critical and
    re-prioritizes; chains are prime needs-runtime items for the red-team phase.
  - **logic-chain finding type** — a single investigate finding may span 2–3 files as a
    multi-primitive chain (`cls: "logic-chain"`).
  - **Codify confirmed as rules** — `sec_harness.rule_gaps.emit_semgrep_rule` drafts a semgrep
    rule from a confirmed syntactic finding (a cheap floor that becomes a mechanical receipt
    next run).
  - **Novelty** — `sec_harness.novelty.upstream_status` (host-side git, opt-in) tells a human
    FIXED/UNFIXED/UNKNOWN before spending runtime effort.

## Phase 6: Multi-pass campaign

The full pipeline (Phases 0–5) runs as one pass. A campaign repeats passes over
one persistent workspace, advancing a git-pinned pass counter and learning across
passes. All coordination state lives in `workspace/state.json` + `findings/`, so a
pass resumes after interruption.

**Per pass, the orchestrator:**
1. `begin_pass(ws, sha)` (pins the current git SHA; increments `pass_number` if the
   prior pass recorded stages).
2. Runs Phases 0–5. After each phase, records completion:
   `uv run python -c "from pathlib import Path; from sec_harness.campaign import record_stage; from sec_harness.workspace import Workspace; record_stage(Workspace(Path('<WS>')), '<stage>')"`
   (the deterministic prefilter, `run_scan`, records `"prefilter"` itself).
3. Ends with `pass_report` for a state + findings-by-status summary.

**Pass N>1 (incremental):**
- Scope to changed code:
  `changed = diffscope.changed_files(<prior_sha>, "HEAD")`.
- Carry settled findings forward with a drift re-check:
  `uv run python -c "from pathlib import Path; from sec_harness.campaign import carry_forward; from sec_harness.workspace import Workspace; print(carry_forward(Workspace(Path('<WS>')), <changed>))"`
  Settled findings (`confirmed`/`fixed`/`rejected`) on changed files become `stale`
  (re-examined this pass); those on unchanged files are kept — the campaign never
  re-litigates stable conclusions but always re-checks code that moved.
- Re-run investigation on `stale` findings + newly-changed files; the FP ladder and
  patch/verify phases proceed as in pass 1 on whatever reaches `raw`.

Full re-scan (pass-1 semantics every pass) is the safe default; incremental scoping
is the token-saving optimization. Finding-id namespacing across incremental prefilter
passes is a known refinement (see Plan 6 notes).

## Context ingestion + postflight (C1/C2)

The harness reads the repo's OWN security context and its own prior scans, and turns
both into scan-driving material — while treating repo docs as untrusted claims.

**Phase C1 — context-ingest** (canonical order: after preflight, BEFORE recon — its leads
feed recon; a recon `attack_surface` class may be added from a lead only if a code indicator
also exists): spawn `agents/context-ingest.md` (sonnet, READ-ONLY). It discovers context docs
(`sec_harness.context.discover_context_files` — `docs/`, `openspec/`, ADRs, `SECURITY*`,
runbooks, `*-review*.md`, `test-findings*`) **and** the prior scan's `kb/prior_context.json`,
distills them into `kb/context.json` (+ `CONTEXT.md`). Every item is trust-tagged
(`untrusted-doc` / `prior-scan`). **C1 verifies now (rework):** for each `claimed_control` it
sets `verify_status` (PRESENT/MISSING/BYPASSABLE) against code and writes MISSING/BYPASSABLE
controls as `CTL-####` **CANDIDATE** findings via `context.control_findings` (evidence
`llm-claimed:doc-claim`, so they cannot confirm on doc text alone). It also carries every
`attack_lead` item forward as a `LEAD-####` **NEEDS_DEPLOYMENT_TESTING** finding via
`context.manual_review_findings(ctx, sha)` — so an out-of-band lead (e.g. a CI deploy-token
path) reaches the red-team plan's manual section instead of vanishing when investigate has no
class to route it to. Then `agents/context-adversary.md` (opus, different family)
pressure-checks the verification (PRESENT-without-proof? finding on doc text alone? missed
bypass? trust-contract breach?) before any later phase consumes it. Both this phase and the
Phase 0-1 phase gates (recon/architecture/threat-model) build their claims with
`sec_harness.phase_gate.claims_from_profile(profile)` / `claims_from_context(ctx)` rather than
hand-rolling `{"id","refs"}` dicts — use these helpers, don't reimplement them. This DRIVES
later phases:
- threat-model imports `context.hunt_rows(ctx)` → trust boundaries + claimed controls
  become prioritized hunt rows;
- investigate imports `context.control_worklist(ctx)` → each **claimed control** is a
  control-verification task ("prove it exists + is effective in code; missing/bypassable
  → finding"); `context.leads(ctx)` add candidates;
- recon may add an attack_surface class from a lead ONLY if a code indicator also exists
  (docs never inflate scope alone).
**Trust contract:** a claimed control is a finding only when investigate proves it missing
with a tool receipt; a doc claim NEVER suppresses a finding and NEVER auto-confirms one.

**Phase C2 — postflight** (after report): `python -m sec_harness.postflight --workspace
<WS> --sha <sha>` distills settled results into the durable `kb/prior_context.json`
(confirmed findings, rejected-with-rationale so they're not re-litigated, drift-keyed by
SHA). Optionally spawn `agents/postflight.md` to add a durable codebase-security-profile
narrative. The NEXT scan's C1 reads this as higher-trust prior context (still drift-checked).

## Per-repo memory (default workspace)

Each scanned repo has a durable memory folder — default `<target>/.sec-harness/<repo-slug>/`,
an in-repo sidecar next to the reviewed code (override the base with `$SEC_HARNESS_HOME`;
the CLI's `--workspace` overrides entirely). The read-only invariant is about the reviewed
SOURCE — the harness never executes or modifies it — NOT about the folder: its own artifacts
live in this `.sec-harness/` sidecar, which is self-ignoring (a seeded `.sec-harness/.gitignore`
keeps scan output out of the repo's git tree). The `<repo-slug>` is keyed by repo identity
(git `origin` URL if present, else path) + a short hash.

The folder IS the campaign workspace and persists across invocations:
- `kb/` — recon `scan-profile.json`, `architecture.md`, `entities/`, `THREAT_MODEL.md`
- `findings/` — every finding (all statuses), `state.json` — campaign state
- `MEMORY.md` — human index: identity, current status, dated learnings log
- `learnings/<date>.md` — dated free-text learnings accumulated across runs
- `runs/` — optional per-run report snapshots

Resume: `RepoMemory(...).run_status()` (CLI: `python -m sec_harness.cli memory --target
<T>`) reads `state.json` and reports `{finished, resumable, next_phase, stages_done}` —
`finished` when `report` is recorded for the active SHA; otherwise `next_phase` is the
first canonical phase not yet recorded. An interrupted campaign resumes there instead of
restarting. Record a learning with `memory --target <T> --learn "..." --tag crypto`.

## Evaluation (bench)

`helpers/bench/` is a dev-only harness that measures + locks detection quality (not part
of a scan): a labelled corpus (positives to find, negatives to stay silent on;
`corpus_seed/` is seeded from real findings) → scan via a swappable adapter → judge →
precision/recall by source & class + FP-rate, and a **regression gate** (a `locked`
finding that stops being detected fails the run). Contract/wiring tests
(`tests/test_contracts.py`, `tests/test_wiring.py`) catch prompt↔schema drift and
silent-backend regressions deterministically. See `bench/README.md`.

## Composition

Phases 0–6 fully implement the multi-pass security-audit campaign pipeline. No
unimplemented phases remain. Per-repo memory + the bench eval harness are additive
infrastructure around that pipeline.
