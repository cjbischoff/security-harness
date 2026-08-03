# Design spec: port codex-security signal/recall mechanisms into sec-harness

**Date:** 2026-08-03
**Status:** Approved for planning
**Scope:** Six additive mechanisms adapted from OpenAI `@openai/codex-security`
(`skills/codex-security/`) into the sec-harness skill. All are additive — no
existing behavior is removed.

---

## 1. Background

`@openai/codex-security` is an LLM-SAST shipped as a Codex plugin: a TypeScript
CLI/SDK, a ~17.7k-LOC Python "workbench" (SQLite durable scan state), and 13
agent skills over schema-validated contracts. It is the same species as
sec-harness (phase pipeline → discovery → validation → attack-path → report) but
made different engineering bets. A three-layer analysis (skills, workbench, TS
orchestration) identified six mechanisms with signal-quality or recall value
that sec-harness verifiably lacks and that fit its philosophy.

**Verified against sec-harness source** (not inferred):

- `fingerprint.py:25` keys identity on `rule_id|cls|file|line` — line shifts
  break cross-pass matching.
- `repo_memory.py` persists rejected findings + learnings but never feeds them
  back into prompts.
- `campaign.py` has no discovery saturation loop; investigate is a single
  recorded stage.
- `coverage.py::compute_coverage` computes SAST *tool-tier* coverage, not a
  surface-completeness ledger with enforced consistency.
- No `cost.py`; `CampaignState.budget` exists as a free-form dict but nothing
  populates it with per-agent usage.
- Schema validation is hand-written Python (`profile.py::validate_profile` →
  `list[str]`), wired via `stage_validate.py` — no jsonschema library.

## 2. Non-negotiable constraints

These bind every feature below (from repo + skill `CLAUDE.md`):

1. **stdlib-only core** — no new runtime dependencies.
2. **Frozen JSON contract** — never add/rename/reorder fields on `Finding` or
   `CampaignState` serialization. The Go port asserts byte-equality of
   `to_dict()` against goldens; any serialization change breaks the other
   workstream's build. New state lives in **new kb/ files**, never on the frozen
   models.
3. **File-based state** — no SQLite engine; all durable state is JSON/Markdown
   under the workspace.
4. **Match existing idioms** — hand-written validators returning `list[str]`;
   append-only `Finding.history` event log; untrusted text wrapped via
   `envelope.py`; prompt hard-rules preserved verbatim.
5. **Git boundary** — touch only `skills/`; explicit-path staging.

## 3. Features

### Feature 1 — Refactor-resistant fingerprints (foundational)

**Problem.** `fingerprint()` includes the raw line number, so a finding that
moves lines between passes is reported by `diff_findings` as both `resolved`
and `new`, corrupting `carry_forward` on pass N>1.

**Design.** Recompute identity as `rule_id | cls | anchor`, where `anchor` is
the **enclosing symbol name** resolved through the Tier-1 evidence substrate
(`graph.py` symbol nodes are keyed `file:line:name`). Add a
`graph.symbol_at(file, line) -> str | None` helper that returns the nearest
enclosing symbol node's `name`. When no symbol resolves (no graph, or a
location outside any symbol), fall back to `basename(file)` plus a normalized
code-shape token so identity degrades gracefully rather than collapsing to a
single bucket. Line number is dropped from identity and retained only as a
locator on the finding.

**Files.** `fingerprint.py` (compute + `diff_findings`), `graph.py`
(`symbol_at`), `dedupe.py` (already calls `fingerprint`; no logic change).

**Contract impact.** None to serialization — the result still lands in the
existing nullable `fingerprint` field.

**Go coordination (required).** The Go port must mirror the new algorithm for
value parity. Goldens stay byte-equal (fixed values), so the build does not
break, but Go's computed fingerprints will diverge until it mirrors the change.
Notify the Go terminal; the spec's algorithm section is the source of truth.

**Acceptance.**
- `fingerprint` is identical for a finding before/after a pure line-shift
  refactor of surrounding code.
- `diff_findings` returns the moved finding under `still_flagged`, not
  `new`+`resolved`.
- Graceful fallback when `graph.json` is absent (no crash; deterministic id).

### Feature 2 — Cross-session false-positive feedback (depends on #1)

**Problem.** Confirmed false positives are persisted (`REJECTED` findings with
a cited reason in `history`/`message`) but never steer later scans.

**Design.** New `fp_feedback.py`: read prior `REJECTED` findings from the
workspace, extract `(cls, message, rejection reason, file:line)`, dedup by
fingerprint (Feature 1), cap at ≤50 most-recent, and render a negative-example
block. The orchestrator injects it into `agents/investigate.md` and
`agents/critic.md` via a new `{{FP_FEEDBACK}}` token. The block is repo-supplied
untrusted text → wrapped in the `envelope.py` trust envelope and labeled
evidence-only, never instructions (mirrors codex's untrusted-data boundary).

**Files.** `fp_feedback.py` (new); `agents/investigate.md`, `agents/critic.md`
(token); `SKILL.md` (orchestration wiring).

**Contract impact.** None.

**Acceptance.**
- A finding rejected in pass N appears as a negative example in pass N+1's
  investigate/critic context.
- Cap and fingerprint-dedup honored; empty history degrades to no block.
- Feedback text is envelope-wrapped.

### Feature 3 — Loop-until-dry discovery saturation (uses #1's dedup)

**Problem.** Investigate runs once per class; there is no recall mechanism that
keeps hunting until discovery is exhausted.

**Design.** Wrap the investigate phase in a bounded convergence loop: dispatch a
discovery wave, dedup new candidates by fingerprint, and terminate when **K
consecutive waves add zero new fingerprints** (`terminal_reason="saturated"`) or
a `max_waves` cap is hit (`terminal_reason="capped"`). State persists in a new
`kb/discovery-ledger.json` (`waves[]`, `consecutive_no_new`, `terminal_reason`,
`k`, `max_waves`) — **not** on `CampaignState`. Defaults `k=2`, `max_waves=5`
(tunable). Existing adversarial coverage gate is unchanged and still runs after
saturation.

**Files.** `discovery_ledger.py` (new); `stage_validate.py` (validator);
`SKILL.md` (loop orchestration); `references/hunting/methodology.md` (document
the convergence contract).

**Contract impact.** None (new kb/ file).

**Acceptance.**
- `consecutive_no_new` resets to 0 on any new fingerprint, else increments.
- Terminal reason is `saturated` at K, `capped` at `max_waves`.
- Ledger validates; loop is deterministic and resumable.

### Feature 4 — Machine-checked coverage completeness

**Problem.** `coverage.py` reports tool-tier coverage but nothing prevents a run
from claiming full coverage while surfaces remain unexamined.

**Design.** New `kb/coverage-ledger.json`: `surfaces[]` each with `disposition`
∈ {reported, no_issue_found, rejected, not_applicable, needs_follow_up},
`deferred[]`, `open_questions[]`, and `completeness` ∈ {complete, partial,
unknown}. Hand-written `validate_coverage_ledger(d) -> list[str]` (matching the
`validate_profile` idiom) enforces codex's invariant: **`completeness=="complete"`
is an error when any surface is `needs_follow_up`, `deferred` is non-empty, or
`open_questions` is non-empty.**
Wired into `stage_validate.py`. Complements — does not replace — `coverage.py`'s
per-language tier accounting. `report.py` renders the ledger (deferred surfaces
and open questions become a visible "coverage gaps" section).

**Files.** `coverage_ledger.py` (new); `references/coverage-ledger.schema.json`
(documentation only); `stage_validate.py`; `report.py`.

**Contract impact.** None.

**Acceptance.**
- Validator rejects an inconsistent "complete" ledger; accepts a consistent one.
- `report.md` surfaces deferred/needs-follow-up items.

### Feature 5 — Per-class proof-tuples + instance-preservation (prompt-only)

**Problem.** Investigate/validate prompts lack explicit per-class
required-evidence checklists, and there is no stated anti-collapse discipline.

**Design.** Add a per-class "proof tuple" (required evidence: attacker-controlled
source + control/sanitizer bypass + reachable impact, specialized per class) to
each `agents/classes/*.md` and to `agents/validate.md`, adapted from codex's
`validation-guidance.md`. Add an explicit **instance-preservation** rule: do not
merge sibling instances that share a CWE family but have distinct concrete sinks
(sec-harness's `dedupe.py` already collapses only exact `file+line+cls`, so this
is a discovery/validation-prompt discipline, not a dedupe change).

**Files.** `agents/classes/{injection,authz,crypto,config,resource}.md`;
`agents/validate.md`; `references/hunting/anti-patterns.md`.

**Contract impact.** None (prose). Load-bearing hard rules preserved verbatim.

**Acceptance.**
- `test_contracts.py` / `test_wiring.py` remain green (prompt↔schema drift).
- Each class prompt carries its proof tuple and the anti-collapse rule.

### Feature 6 — Cost/token accounting

**Problem.** No per-run cost visibility for a fan-out-heavy pipeline.

**Design.** New `cost.py`: the orchestrator records per-agent
`{phase, agent, model, tokens}` entries into the existing free-form
`CampaignState.budget` dict. `cost.py` aggregates by phase and prices via a
small `model → rate` table; `report.py` renders a cost summary. Architecture
note (honest): sec-harness is driven by the main Claude agent spawning subagents
via the Agent tool, not a separate process tailing session JSONL, so this is a
recorded-usage model — lower fidelity than codex's automatic `parentThreadId`
BFS attribution, but it fits the harness's control flow.

**Files.** `cost.py` (new); `report.py`; `SKILL.md` (recording convention).

**Contract impact.** None — `budget` is already an untyped dict in the frozen
`CampaignState`.

**Acceptance.**
- Aggregation by phase is correct; pricing table applied.
- `report.md` renders a cost summary; empty budget degrades cleanly.

## 4. Sequencing

`#1 → #2 → #3` is a dependency chain (stable identity → feedback matching →
saturation dedup). `#4`, `#5`, `#6` are independent and may be done in any order.
The implementation plan will phase them accordingly.

## 5. Out of scope (analyzed, deliberately not ported)

- **SQLite workbench engine** — conflicts with file-based/stdlib/Go-mirror
  design. Concepts (logical-finding vs occurrence, decision ledger) partially
  adopted via kb/ files where valuable; the engine is not.
- **Remediation optimistic-concurrency + lease state machine** — solves
  multi-host-thread contention sec-harness does not have (single orchestrator,
  throwaway-copy patches). YAGNI.
- **report.md as deterministic projection** — sec-harness already does this
  (`report.py`).
- **Trusted-executable / PATH-hijack / schema-complexity governor / bulk
  multi-repo** — smaller attack surface (never executes target) and different
  product scope.

## 6. Global acceptance

- `uv run pytest -q` green except the documented env-only failures.
- `uv run ruff check` and `uv run ty check` clean (zero new diagnostics) in
  touched modules.
- No change to `models.py` / `evidence.py`; no staged paths outside `skills/`.
- Each new module has TDD tests written red-first.
