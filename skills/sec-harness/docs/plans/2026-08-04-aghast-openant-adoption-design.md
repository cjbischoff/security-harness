# Design: adopting select aghast/OpenAnt capabilities into sec-harness

**Date:** 2026-08-04
**Status:** approved (design), pending implementation plan
**Scope:** `skills/sec-harness/` only

## Background

Two external tools were reviewed for capabilities sec-harness lacks:

- **aghast** (`/Users/christopher/Tools/aghast`) — a TypeScript CLI that lets a security
  team encode organization-specific policy checks (JSON + Markdown + optional Semgrep
  rule) and runs them through an LLM agent, with Semgrep/SARIF/OpenAnt as discovery
  layers. Its FP-reduction is entirely single-model prompt discipline — no adversarial
  validation, no dedup beyond exact `file:line`, no computed severity.
- **OpenAnt** (`/Users/christopher/Tools/OpenAnt`) — a Go CLI + Python core (Anthropic
  API + Docker dependent) that aghast wraps as a discovery layer. Its *base dataset*
  (the `parse` step: unit extraction, call graph, BFS reachability, regex-based
  entry-point detection) is deterministic and LLM-free; its *enhanced dataset* and
  Stage-1/2 analysis are LLM-driven and out of scope here — reusing them would require
  an Anthropic-API dependency and would contaminate the independent-judgment principle
  sec-harness's adversarial validation already relies on.

Neither tool is adopted as a dependency. sec-harness stays stdlib-only
(`skills/sec-harness/CLAUDE.md` §7); no Anthropic SDK, no Go/Node toolchain. What
follows are four independently-scoped internal changes inspired by specific mechanisms
in those tools, re-implemented natively.

Comparison summary (full detail in conversation, not reproduced here): sec-harness
already exceeds both tools on adversarial validation (critic→judge→validate→trace on a
different model family), dedup (refactor-resistant fingerprint), computed severity
(CVSS via `calibrate`), incremental/diff-scoped scanning, and SCA/secrets coverage.
The four gaps below are genuine.

---

## A. Custom check bundles

**Problem:** sec-harness's `investigate` agents only know generic, cross-repo attack
classes (`references/attack-classes.md`). There is no mechanism for a team to encode
its own business-logic policy — e.g. "every payment endpoint re-derives price from the
database, never trusts a client-supplied amount" — as a reusable, repo-scoped check.

**Design:**

- **Location:** `.sec-harness/checks/<check-id>/` inside the target repo (checked in
  by the org that owns the repo, versioned alongside the code it describes). No
  external registry, no repo-name matching — a check bundle found in a repo always
  applies to that repo.
- **Bundle shape**, per `<check-id>/`:
  - `<check-id>.json` — `{name, severity, instructionsFile, semgrepRule?, applicablePaths?, excludedPaths?}`
  - `<check-id>.md` — instructions, written in the same register as `agents/*.md`
    prompts (imperative, cites what to look for and what counts as a finding)
  - optional `<check-id>.yaml` — a Semgrep rule used only to *scope* which files/lines
    get sent to the check; not itself a finding source (mirrors how prefilter Semgrep
    hits become `candidate` findings, not confirmed ones)
- **Discovery:** a new deterministic loader, `sec_harness.custom_checks`, scans
  `.sec-harness/checks/` during recon/prefilter setup and registers each check as an
  additional attack-class entry, the same shape `attack-classes.md`-derived classes
  take in `agents_to_spawn`.
- **Execution:** each custom check is dispatched through the **existing**
  `agents/investigate.md` machinery — its markdown instructions are appended to the
  standard prompt after the shared `prompt-constants.md` blocks (`ANTI_MANIPULATION`,
  `TOOL_TRUST`, `SEVERITY_PRECONDITION`, etc.), so a custom check gets the same trust
  envelope as every built-in class. No new agent prompt type.
- **Rigor:** custom-check candidates go through the full existing gate ladder —
  dedupe, critic → judge → validate → trace, calibrate. This was an explicit decision:
  unlike aghast, sec-harness does not offer a lighter-weight path for org-authored
  checks. A finding must survive the same adversary on a different model family
  regardless of who wrote the check that found it.
- **Unrouted-candidate accounting:** custom-check classes must be included in
  `agents_to_spawn` bookkeeping so `unrouted_candidate_classes` (existing hard rule,
  §3 of `CLAUDE.md`) doesn't orphan them.

**Out of scope for this iteration:** an external multi-repo check registry (aghast's
`checks-config.json` + `repositories` matching). If a need emerges for org-wide checks
shared across many repos, that's a separate follow-on design — the in-repo model is
simpler and matches the current ask.

---

## B. Structured-output hardening

**Problem:** `findings_gate.py:14-59` validates only 4 things about a written
`findings/*.json` file (non-empty `file`, `line >= 1`, `dataflow` is a list, and the
tool-receipt requirement for `confirmed`/`fixed`). `Finding` has no formal JSON schema,
unlike `scan-profile.json`, `fix-disposition.json`, and `coverage-ledger.json`, which
each have one under `references/*.schema.json`.

**Design:**

- Add `references/finding.schema.json`, a JSON Schema mirroring the full `Finding`
  field set in `models.py` (types, enum values incl. the hyphenated
  `needs-deployment-testing`, required vs optional fields).
- `findings_gate.py` validates every finding against this schema in addition to (not
  instead of) the existing semantic checks (tool-receipt gate, `duplicate_of`
  consistency) — schema validation catches shape errors, the semantic checks stay
  because they encode business rules a generic schema can't express (e.g. "tool
  receipt required only when status is confirmed/fixed").
- Same treatment for `kb/discovery-ledger.json` and `kb/gates/*.json` if inspection
  during implementation shows they currently lack schemas.
- No new dependency: hand-rolled schema validation using stdlib `json`, following the
  same pattern already used for the three existing schemas (confirm during
  implementation whether those are validated with a hand-rolled checker or an existing
  helper, and reuse whichever it is).
- This does **not** change how agents are invoked (subagent dispatch via Task tool,
  markdown prompts) — only strengthens the after-the-fact validation gate. The
  Anthropic-SDK/structured-tool-output path (aghast's model) was explicitly rejected
  to avoid adding a first runtime dependency to sec-harness's core.

---

## C. Cross-target anti-hallucination guard

**Problem:** `investigate.md:58-64` has each attack-class agent working a **worklist
of many candidates** in a single context — explicitly ">~40 candidates for large
buckets like xss," grouped by sink pattern/file. Gate −1 (sanity/hallucination) already
rejects a finding whose cited `file:line` doesn't exist or doesn't match the described
code — but it does not catch the case where the cited location *is* real and *is* a
genuine sink, just belongs to a **different candidate in the same batch** (attribution
swap between two similar-looking sinks processed in one pass).

**Design:**

- Add an explicit self-check instruction to `investigate.md`'s output step: before
  writing a finding for candidate *N*, the agent must confirm the `file`/`line` it is
  about to emit matches candidate *N*'s original location, not a sibling candidate's.
- If this shape (one agent, many candidates, risk of cross-attribution) recurs in
  other multi-candidate agents (`critic.md`, `patch.md`), promote the instruction to a
  reusable block in `prompt-constants.md` rather than duplicating prose across prompt
  files — confirm scope during implementation by checking those prompts' worklist
  structure.
- Prompt-only change. No code changes, no schema changes.

---

## D. Deterministic entry-point detection (Tier-1 graph substrate)

**Problem:** `graph.py`'s Tier-1 substrate (`build_tier1`, `graph.py:151`) has BFS
reachability (`reaches`, `no_path` — a disproof receipt) and call/import/taint edges,
but no deterministic notion of "this function is an entry point reachable from outside
the process." That knowledge today comes entirely from the `recon` agent's LLM
judgment (`kb/scan-profile.json`'s `attack_surface`), which is not tool-receipt backed.

**Design:**

- Add entry-point classification to Tier-1 build: regex-based detection of route
  decorators/handlers, CLI-arg patterns, and user-input access patterns
  (`request.*`, `sys.argv`, `os.environ[`, etc.) per language already known to
  `_lang_of` (`graph.py:145`).
- Tag matching `Node`s with `is_entry_point: bool` and `entry_point_reason: str`,
  computed unconditionally as part of Tier-1 (consistent with the existing hard rule
  that "the Tier-1 substrate is always built, never behind a flag" — CLAUDE.md §3).
- Consumers: `no_path`/`attacker_controls` gain a deterministic, receipt-backed seed
  set for source-reachability queries instead of relying solely on LLM-asserted
  `attack_surface`; `phase-adversary.md`/`threat-model` gain a mechanical cross-check
  against the LLM's claimed attack surface (flag a mismatch as a knowledge gap rather
  than silently trusting either source).
- Explicitly **not** ported: OpenAnt's *enhanced*-dataset security-classification
  (LLM-derived `exploitable`/`vulnerable_internal`/`security_control`/`neutral`
  labels) and its two-stage attacker-simulation analysis — these require an
  Anthropic-API dependency and would duplicate/contaminate sec-harness's own
  independent-judgment adversarial pipeline.

---

## Testing

- **A:** unit tests for `sec_harness.custom_checks` discovery (bundle parsing,
  malformed bundle handling, missing files); integration test confirming a custom
  check's candidates flow through the same gate ladder as a built-in class (reuse
  existing investigate/gate/dedupe test fixtures where possible).
- **B:** schema validation tests using both valid and deliberately malformed
  `Finding` dicts (missing required field, wrong enum value, wrong type) — must fail
  the gate; existing valid fixtures (`fixtures/golden_raw_finding.json`) must still
  pass.
- **C:** no automated test (prompt-only change) — verify via a dogfooding run with a
  large candidate bucket (e.g. xss on a repo with many similar sinks) that per-finding
  attribution stays correct; consider a targeted bench corpus case if one doesn't
  exist.
- **D:** unit tests for entry-point regex detection per supported language (true
  positives: known route/CLI/user-input patterns; true negatives: internal-only
  functions); confirm `build_tier1` always computes this (no flag to disable).

## Non-goals

- No Anthropic SDK / direct API dependency (explicitly rejected).
- No external multi-repo check registry (deferred; in-repo bundles only for now).
- No adoption of OpenAnt's LLM-enhanced dataset or attacker-simulation stages.
- No change to how agents are dispatched (Task-tool subagents, not direct SDK calls).
