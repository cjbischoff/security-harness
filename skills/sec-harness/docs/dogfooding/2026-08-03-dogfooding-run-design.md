# Design spec: instrumented dogfooding run of sec-harness

**Date:** 2026-08-03
**Status:** Approved (via clarifying-question round)
**Branch:** `skill-dogfood-fixes-20260803`

## Objective

Two deliverables from one instrumented pass:

1. **Real audit artifacts** for three target repos (threat model, findings JSON,
   SARIF, Markdown report, redteam plan each).
2. **A runtime-issues report** capturing every gap, bug, inefficiency, wasted
   effort, and poor-data moment observed while driving the full agentic
   pipeline — with fixes for the blockers and a triaged fix-batch for the rest.

## Targets

| Order | Repo | Size | Languages |
|-------|------|------|-----------|
| 1 (shakedown) | ai-platform | 7.1M / 292 files | TypeScript |
| 2 | accounting-integrations | 25M / 939 files | JS/TS |
| 3 | ai-scheduler | 105M / 809 files | Python + TS |

## Method

Drive the full agentic pipeline **one phase at a time, instrumented** (per
`SKILL.md` phase order). Deterministic steps run via
`uv run python -m sec_harness.*`; agent phases spawn subagents with the
`agents/*.md` prompts. After each phase, record: outputs present + valid, data
looks right (not empty/garbage/hallucinated), timing/cost, and any wasted or
duplicated work.

**Shakedown-first:** run ai-platform fully, capture issues, fix blockers, then
run repos 2 and 3 with fixes applied (don't pay for the same bug 3×).

**Budget:** run fully, no artificial cap; record per-phase spend via `cost.py`.

**ai-scheduler (105M):** let recon profile it, then scope investigate to the
highest-signal subsystems recon surfaces; log every deferral to the coverage
ledger — never silently drop.

## Per-phase watch checklist

- **Preflight/graph** — all planned backends present; `graph.json` built,
  non-empty, edges resolve.
- **Recon/architecture/threat-model** — outputs cite real `file:line`; hunt
  list evidence-based not guessed; opus adversary ran on a different family.
- **Prefilter** — every planned backend in `backends_run`; nothing silently in
  `failed`/`skipped`; candidate counts sane; no orphaned candidate classes.
- **Investigate** — saturation loop terminates (`saturated`/`capped`, not
  hung); FP-feedback injected on pass N>1; gate-ladder receipts recorded;
  recall not collapsed.
- **Critic/judge/validate/trace** — model-family diversity honored;
  tool-receipt gate blocks LLM-only confirms; no `verify-error` laundered clean.
- **Calibrate/patch/verify/redteam/report** — CVSS computed not asserted;
  patches on throwaway copy only; SARIF valid; redteam plan uses `$VARS`.

## Issue taxonomy

Each logged with phase, evidence (`file:line` or command output), and severity:

- `blocker` — run cannot proceed.
- `correctness` — wrong data or a weakened gate.
- `data-quality` — empty / garbage / hallucinated / misrouted output.
- `efficiency` — slow or redundant backend/dispatch.
- `wasted-effort` — re-doing settled work, over-fanned waves.

## Fix gate

- **Blockers** → fix immediately on the branch, red-green TDD, respecting the
  frozen JSON contract (no `models.py` / `evidence.py` edits without flagging
  the Go terminal).
- **Everything else** → `runtime-issues_20260803.md` → user triage/approval →
  writing-plans plan → subagent-driven-development.

## Constraints

- stdlib-only core; frozen contract byte-for-byte with the Go port.
- Git boundary: stage only `skills/` paths; never commit to `main`.
- Harness never executes or modifies target source; workspace sidecar is the
  only write surface (`<target>/.sec-harness/<slug>/`).

## Artifacts

- Per-repo: `<target>/.sec-harness/<slug>/` (kb/, findings/, report.*, redteam).
- Observations: `skills/sec-harness/docs/dogfooding/runtime-issues_20260803.md`.
- Raw per-phase logs: job tmp dir.
