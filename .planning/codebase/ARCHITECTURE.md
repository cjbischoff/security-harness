<!-- refreshed: 2026-07-30 -->
# Architecture

**Analysis Date:** 2026-07-30

**Scope:** `skills/sec-harness/` only. This is the Python reference implementation; a
Go rewrite is planned (`docs/sec-harness-go-migration-context.md`, not covered here).

## System Overview

```text
┌─────────────────────────────────────────────────────────────────────┐
│  MAIN AGENT (orchestrator, driven by SKILL.md)                        │
│  spawns LLM subagents + calls deterministic `python -m` CLIs in order │
└───────────────┬───────────────────────────────┬──────────────────────┘
                │                                │
    ┌───────────▼─────────────┐     ┌────────────▼─────────────────────┐
    │  LLM PHASES (prompts)    │     │  DETERMINISTIC CORE (Python)      │
    │  agents/*.md             │     │  helpers/sec_harness/  (~57 mods) │
    │  recon, architecture,    │     │  prefilter, dedupe, calibrate,    │
    │  threat-model, investigate│    │  verify, findings_gate, redteam,  │
    │  critic, validate, patch, │    │  report, phase_gate, campaign     │
    │  redteam, trace, judge…   │     │                                   │
    └───────────┬─────────────┘     └────────────┬─────────────────────┘
                │                                │
                └────────────┬───────────────────┘
                             ▼
        ┌─────────────────────────────────────────────────────┐
        │  WORKSPACE / KB  (the shared filesystem contract)     │
        │  `findings/<ID>.json`  (Finding schema = phase contract)│
        │  `kb/` (scan-profile, architecture, THREAT_MODEL,     │
        │         context.json, gates/<phase>.json, tuning/)    │
        │  `state.json` (campaign pass counter, pinned SHA)     │
        │  `report.sarif` · `report.md` · `redteam-plan.md`     │
        └─────────────────────────────────────────────────────┘
```

## Core Pattern: deterministic core + LLM-agent prompts + tool-receipt gate

Three cooperating layers, no framework glue:

1. **Deterministic Python core** (`helpers/sec_harness/`, ~57 modules). Pure, testable,
   idempotent. Owns SAST invocation, normalization, dedupe, scoring, verification,
   gating, reporting, campaign state. Never calls an LLM. Each concern is one small
   module; many expose a `python -m` CLI.
2. **LLM-agent prompts** (`agents/*.md`). Markdown prompt templates with `{{TARGET}}`,
   `{{WORKSPACE}}`, `{{ATTACK_CLASS}}`, `{{PHASE}}`, `{{ROUND}}` substitution slots.
   The main agent spawns each as a subagent (sonnet for producers, opus for
   adversaries/validators). Prompts read/write the workspace; they never mutate target code.
3. **Tool-receipt gate** (`evidence.py`). The trust boundary between layers. A finding's
   `evidence_sources` are either mechanical **tool receipts** (`semgrep:<rule>`,
   `codeql:dataflow`, `ast-grep:sink`, `structural-index:callers`) or `llm-claimed:*`
   assertions. `evidence.is_tool_receipt` / `confidence_for` enforce that a finding with
   only `llm-claimed:*` sources can NEVER reach `confirmed` — the LLM's hallucination risk
   is suppressed only by a mechanical receipt.

**Adversarial-review invariant:** every phase that emits findings or context a later phase
consumes is challenged by an independent adversary (different model family, fresh context)
before its output flows forward. Findings use the FP ladder (critic + adversarial-validate);
analysis/context phases use the phase-adversary gate (`phase_gate.py` + `agents/phase-adversary.md`).

## The Finding schema — contract between phases

`Finding` (`helpers/sec_harness/models.py`) is the frozen contract. One JSON file per
finding at `findings/<ID>.json` (via `workspace.write_findings` / `read_findings`). Every
phase reads findings, mutates fields, writes them back. `from_dict` tolerates unknown keys
(forward-compat across schema versions).

Key lifecycle fields:
- `status` (`FindingStatus`): `candidate → raw → confirmed → fixed`, plus `rejected`,
  `duplicate`, `stale`, `needs-deployment-testing`. Drives the ladder and multi-pass logic.
- `evidence_sources`: tool-receipt vs `llm-claimed:*` (the trust gate).
- `risk_score` (calibrate), `verification` (verify: `verified-static|static-only|not-fixed|verify-error`),
  `patch_diff` (patch), `reachability` (trace), `runtime_disposition`/`runtime_test` (redteam),
  `judge_verdict` (judge), `preconditions` (severity cap), `fingerprint` (dedupe/carry-forward).
- `id` is **class-prefixed** for investigate findings (`SQLI-0001`) so parallel per-class agents
  never contend on id allocation; deterministic prefilter uses `C-####`/`F-####`.

`CampaignState` (same file) holds `pass_number`, `active_sha`, `stages`, `budget`; persisted to
`state.json`.

## Phase Pipeline

One audit pass runs these in order (SKILL.md is authoritative). Adversary-gated phases marked †.

| # | Phase | Kind | Prompt / module |
|---|-------|------|-----------------|
| 0 | Preflight | det | `python -m sec_harness.preflight` (backend/pack presence) |
| 1 | Begin pass | det | `state.begin_pass(ws, sha)` |
| C1 | Context-ingest † | LLM sonnet + opus adversary | `agents/context-ingest.md`, `agents/context-adversary.md`, `context.py` |
| 2 | Recon † | LLM sonnet | `agents/recon.md` → `kb/scan-profile.json` (`profile.load_profile`) |
| 3 | Architecture † | LLM sonnet | `agents/architecture.md` → `kb/architecture.md`, `kb/entities/` |
| 4 | Threat model † | LLM sonnet | `agents/threat-model.md` → `kb/THREAT_MODEL.md` |
| 0.5 | Tool tuning (opt) | LLM sonnet, ratcheted | `agents/tune-config.md`, `tuning.py` |
| 5 | Prefilter (SAST) | det | `prefilter.run_prefilter(ws, target, profile)` |
| 6 | Investigate | LLM sonnet, parallel per class | `agents/investigate.md`, `agents/classes/*.md`, `partition.py` |
| 7 | Dedupe | det | `python -m sec_harness.dedupe` |
| 8 | Critic | LLM sonnet, parallel | `agents/critic.md` |
| — | Judge (cheap) | LLM no-tools | `agents/judge.md` |
| 9 | Adversarial-validate | LLM opus, DIFFERENT family | `agents/validate.md` |
| 10 | Calibrate | det | `python -m sec_harness.calibrate` → `risk_score` |
| — | Trace/reachability (opt) | LLM opus | `agents/trace.md`, `reachability.py` |
| 11 | Patch | LLM opus, parallel | `agents/patch.md` |
| — | Validate-fix | LLM opus | `agents/validate-fix.md`, `scoring.score_fix` |
| 12 | Verify | det | `python -m sec_harness.verify` (apply patch to copy, re-scan) |
| 13 | Gate | det | `python -m sec_harness.findings_gate` |
| 13.5 | Red Team † | LLM sonnet + opus adversary | `agents/redteam.md`, `agents/redteam-adversary.md`, `redteam.py` |
| 14 | Report | det | `python -m sec_harness.report` → SARIF + md |
| C2 | Postflight | det (+ opt LLM) | `python -m sec_harness.postflight`, `agents/postflight.md` |

Recall/grounding side-loops: variant-hunt (`variant.py`, `agents/variant-hunt.md`),
bug-chain (`python -m sec_harness.bugchain`, `agents/bugchain.md`), git-history mining
(`githist.py`), rule-gap codification (`rule_gaps.py`), novelty check (`novelty.py`),
fact-check (`factcheck.py`, `agents/factcheck.md`).

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| Finding / CampaignState models | Frozen inter-phase contract | `helpers/sec_harness/models.py` |
| Workspace | KB/findings/report filesystem layout + per-finding JSON I/O | `helpers/sec_harness/workspace.py` |
| Prefilter | Concurrent SAST (semgrep/codeql) → merged deterministic `C-####` candidates | `helpers/sec_harness/prefilter.py` |
| Evidence | Tool-receipt vs llm-claimed classification (the trust gate) | `helpers/sec_harness/evidence.py` |
| Phase gate | Deterministic ref-resolution pre-check + adversary record for context phases | `helpers/sec_harness/phase_gate.py` |
| Gates (fix) | Fail-closed quality-gate orchestrator (`GATE_ROUTING`/`REQUIRED_GATES`) | `helpers/sec_harness/gates.py` |
| Findings gate | Schema-conformance gate over all findings (exit 1 on invalid) | `helpers/sec_harness/findings_gate.py` |
| Calibrate | Risk score 1–10 with precondition cap | `helpers/sec_harness/calibrate.py` |
| Verify | Apply patch to throwaway copy, re-scan, compare class presence | `helpers/sec_harness/verify.py` |
| Report | Final SARIF 2.1.0 + Markdown (confirmed/fixed only) | `helpers/sec_harness/report.py`, `sarif.py` |
| Reachability | Sink→entry backward-trace verdict + blocker taxonomy | `helpers/sec_harness/reachability.py` |
| Red team | Static→runtime bridge; renders `redteam-plan.md` | `helpers/sec_harness/redteam.py` |
| Context | Ingest repo security docs as untrusted claims → hunt rows/worklist | `helpers/sec_harness/context.py` |
| Campaign | Stage recording, salvage, carry-forward, pass reporting | `helpers/sec_harness/campaign.py`, `state.py` |
| Repo memory | Durable per-repo workspace under `~/.sec-harness/<slug>/` | `helpers/sec_harness/repo_memory.py` |

## Layers

**Deterministic core** — `helpers/sec_harness/`. Depends on: stdlib, external SAST binaries
(semgrep/codeql/ast-grep via subprocess), `rg`. Used by: the CLIs and the main agent.

**Agent prompts** — `agents/`. Depend on: workspace files + `references/` (prompt-constants,
attack-classes, finding-template) + `references/hunting/` methodology. Used by: main agent
via the Agent/Task tool.

**Workspace/KB** — the filesystem. The only shared state; enables crash-resume and
parallel agents (no in-memory coordination).

## Data Flow

### Primary path (one pass)

1. Preflight verifies backends/packs (`preflight.py`).
2. Recon/architecture/threat-model agents write `kb/*`, each phase-gated (`phase_gate.py`).
3. `prefilter.run_prefilter` runs SAST concurrently → `candidate` findings (`C-####`).
4. `partition.partition_candidates_by_class` groups candidates; investigate agents (one per
   class, dispatched in ONE message) triage → `raw`/`rejected`/new class-prefixed findings.
5. FP ladder: dedupe → critic → judge → adversarial-validate (opus, different family) →
   `confirmed`. Only tool-receipt-backed findings can confirm (`evidence.py`).
6. Calibrate sets `risk_score`; patch writes `patch_diff`; verify applies to a copy and
   grades `verification`; `findings_gate` schema-checks.
7. Red-team sets `runtime_disposition`/`runtime_test`, adversary strips weak items,
   `redteam.py` renders `redteam-plan.md`.
8. Report emits SARIF + md (confirmed/fixed only). Postflight distills durable
   `kb/prior_context.json`.

### Multi-pass (pass N>1)

`state.begin_pass` pins SHA + increments; `diffscope.changed_files` scopes to changed code;
`campaign.carry_forward` marks settled findings on changed files `stale` (re-examined) and
keeps conclusions on unchanged files. `campaign.record_stage` after each phase drives resume.

**State management:** entirely file-based. `state.json` (`CampaignState`) + `findings/*.json`
are the source of truth; any phase resumes from what's recorded.

## Key Abstractions

- **Finding** — the lifecycle object and inter-phase contract (`models.py`).
- **Workspace** — path resolver + finding persistence (`workspace.py`).
- **ScanProfile** — recon output driving backend selection + agent fan-out (`profile.py`).
- **Tool receipt** — mechanical evidence source gating confirmation (`evidence.py`).
- **Gate record** — adversary verdict artifact at `kb/gates/<phase>.json` (`phase_gate.py`).

## Entry Points

- **`sec_harness.cli`** (`helpers/sec_harness/cli.py`): `scan` (deterministic pipeline via
  `run_scan`) and `memory` (per-repo status/learnings). `main()` under `python -m sec_harness.cli`.
- **Per-module `python -m` CLIs**: `preflight`, `dedupe`, `calibrate`, `verify`,
  `findings_gate`, `redteam`, `report`, `postflight`, `structural_index`, `bugchain`,
  `astgrep`, `citations`, `redactor`, `rule_gaps` — each a phase step the main agent invokes.
- **Agent prompts** (`agents/*.md`): spawned by the main agent, not directly executable.

## Architectural Constraints

- **Read-only on target.** The harness NEVER executes or mutates scanned code. Patches apply
  only to a throwaway copy in `verify.py`. Memory lives outside the target (`repo_memory.py`).
- **Independence guard.** Adversarial-validate/redteam-adversary MUST be a different model
  family (opus) than the sonnet producer; degradation to fresh-context is logged, never silent.
- **Determinism.** Prefilter merges concurrent backend results sorted with stable `C-####` ids
  so serial and concurrent runs are byte-identical.
- **Fail-closed gates.** `gates.REQUIRED_GATES` fails the run if a required gate emitted zero
  invocations (routing drift can't vacuously pass); missing result hard-fails.
- **No shared in-memory state.** Parallel agents coordinate only through `findings/*.json`
  and class-prefixed ids.

## Anti-Patterns

### Inferring phase completion from a single output file

**What happens:** treating `architecture.md` existing as "architecture phase done".
**Why it's wrong:** an agent can crash after one write but before `kb/entities/*`.
**Do this instead:** a phase is done only when ALL outputs exist AND `campaign.record_stage` ran.

### Confirming on LLM assertion alone

**What happens:** promoting a finding whose `evidence_sources` are all `llm-claimed:*`.
**Why it's wrong:** no mechanical receipt suppresses hallucination risk.
**Do this instead:** `evidence.confidence_for` / the validate gate keep it non-`confirmed`
until a tool receipt (`semgrep:*`/`codeql:*`/`ast-grep:*`/`structural-index:*`) exists.

### Reporting a partial scan as clean

**What happens:** semgrep runs, codeql pack is missing, "0 findings" reported.
**Why it's wrong:** a missing query pack = zero dataflow coverage for that language.
**Do this instead:** STOP if `backends_run` is empty or any planned backend is in
`failed`/`skipped_reasons` (`prefilter.run_prefilter` return dict).

### Orphaning candidates outside `agents_to_spawn`

**What happens:** `security-other`/`unknown` candidates (command-exec, weak-crypto) dropped.
**Why it's wrong:** high-value vendored-rule hits carry no `cls`/CWE.
**Do this instead:** `partition.unrouted_candidate_classes`; spawn a general-triage agent.

## Error Handling

**Strategy:** fail-open parsing + explicit terminal states + salvage.

- `parse.extract_json` returns `None` on failure so a parse miss is surfaced, never mistaken
  for "nothing found".
- `stage_validate.validate_stage` + `repair_prompt` re-prompt the same subagent with the exact
  errors (bounded attempts).
- `campaign.salvage_partial` stamps pre-crash findings `salvaged`; `campaign.TERMINAL_STATUSES`
  marks what resume must not re-run. `verify-error` is a valid terminal state.

## Cross-Cutting Concerns

**Trust envelope:** all agents import `references/prompt-constants.md` and wrap untrusted repo
text in a trust envelope (`envelope.py`). **Redaction:** `redactor.py` scrubs secrets from
output. **Validation:** `findings_gate.py` (schema) + `phase_gate.py` (ref resolution) +
`gates.py` (fix quality). **Evidence/confidence:** `evidence.py` centrally.

---

*Architecture analysis: 2026-07-30*
