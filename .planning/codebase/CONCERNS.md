# Codebase Concerns

**Analysis Date:** 2026-07-30

Scope: `skills/sec-harness/` only. Framed for the planned **Python → Go port**
of the harness into a self-contained, API-key-only, headless binary. The
deterministic core is solid and well-tested (51 test files, 202 passing per the
migration brief); these concerns are the seams and debts that matter when the
core is re-hosted in Go with a hand-rolled Anthropic tool loop.

---

## Tech Debt

**Orchestration lives in Markdown prose, not code (THE central port seam):**
- Issue: The entire phase sequence, fan-out policy, retry/backoff guidance,
  wave-batching, model routing, and phase-completion contract are English prose
  in `SKILL.md` (450 lines), executed by whatever LLM drives the Claude Code
  harness. There is no code that enforces phase order, checks "all outputs
  present AND stage recorded," or bounds concurrency — those are instructions a
  model is asked to follow (`SKILL.md:114-119`, `SKILL.md:189-196`).
- Files: `SKILL.md`, all of `agents/*.md`.
- Impact: This is the single largest non-mechanical part of the port. The Go
  "orchestrator" layer (migration doc layer 3) must be written from scratch —
  the prose is a blueprint, not portable code. Every guarantee currently
  phrased as "the main agent should…" becomes a code invariant (sequence,
  assertion, semaphore, retry).
- Fix approach: Convert `SKILL.md` phase flow into an explicit state machine in
  Go. Each prose "Robustness" note (`SKILL.md:189-196`) becomes a code
  construct: wave-batching → semaphore; "retry with backoff" → the official
  client's `max_retries`; "skip terminal candidates" → a worklist filter over
  `state.json`; "phase done only when all outputs exist AND record_stage ran" →
  a completion assertion.

**Safety helpers `envelope.py` / `redactor.py` are effectively dead controls:**
- Issue: `helpers/sec_harness/envelope.py` (`wrap_untrusted`, `neutralize_markers`,
  `attribution_banner`) and `helpers/sec_harness/redactor.py` (`safe_for_prompt`,
  `verify_no_secrets`) have **zero callers** anywhere in `helpers/sec_harness/`,
  `agents/`, or `SKILL.md`. They are exercised only by their own unit tests
  (`helpers/tests/test_envelope.py`, `test_redactor.py`,
  `test_factcheck_baseline_envelope.py`).
- Files: `helpers/sec_harness/envelope.py`, `helpers/sec_harness/redactor.py`.
- Impact: The "untrusted repo content is enveloped before entering a prompt" and
  "secrets are redacted before any prompt" controls exist as tested code but are
  **never actually invoked in the pipeline**. Prompt injection defense and
  secret-leak defense are currently prompt-level only — the agent prompts *ask*
  the model to envelope quoted text (`agents/investigate.md:13`,
  `agents/critic.md:12`, `agents/context-adversary.md:12`), so enforcement
  depends on model compliance, not code. In the CC skill there is no code path
  that constructs prompts, so there is nowhere for these helpers to be called.
- Fix approach: In Go, prompt assembly IS code (the tool loop builds every
  message). Wire `wrap_untrusted`/`safe_for_prompt` into the single prompt-build
  chokepoint so every repo-derived string is enveloped + redacted in code before
  send — turning two well-designed but orphaned controls into enforced ones.
  This is called out in the migration brief's "robustness gaps that become free
  in code" theme and is one of the highest-value wins of the port.

**Structural index is rg-based and weak on PHP/OO (deferred to Go):**
- Issue: `helpers/sec_harness/structural_index.py` navigates via `rg` plus
  indentation/brace heuristics. `list_definitions` only recognizes Python
  `def`/`class` and JS `function`/`const`/`let`/`var` (`structural_index.py:16-18`);
  there are no PHP, Java, Ruby, or Go definition patterns. `get_function_boundary`
  falls back to a single line for any unknown language
  (`structural_index.py:86-88`, marked `ponytail:`). `find_callers` is a
  word-regex grep, not a call graph (`structural_index.py:91-125`).
- Files: `helpers/sec_harness/structural_index.py`.
- Impact: Gate 1 (reachability) is the harness's most-cited gate, and it runs on
  a text-search index. On PHP/OO targets (the SNaaP + batch-2 runs) `callers`
  returned class/instantiation noise, method-level `defs` failed, and
  test-vs-prod tagging had to be eyeballed. `ripgrep:` receipts are weaker
  grounding than a real AST would give.
- Fix approach: Build the tree-sitter call-graph indexer natively in Go
  (migration doc "F4"), matching the current CLI query surface so agent prompts
  are unchanged, and degrade to the rg path when a grammar is missing. Port the
  test/prod caller tagging (`structural_index.py:128-144`) forward — that
  behavior is worth keeping.

**Two `ponytail:` basename-match shortcuts (known ceilings):**
- Issue: `campaign.py:111` and `verify.py:154` match files by basename, which
  aliases same-named files in different directories.
- Files: `helpers/sec_harness/campaign.py`, `helpers/sec_harness/verify.py`.
- Impact: Low today (distinct filenames), but a target with two `config.py`s in
  different packages could cross-wire carry-forward or verification. The
  upgrade path (full relative paths) is noted in the comments.
- Fix approach: Use repo-relative paths as keys when porting these two functions.

---

## Fragile Areas

**Provider-load fragility in the fan-out (429/529) — no code enforcement:**
- Files: `SKILL.md:189-196` (the only place this is addressed).
- Why fragile: The prescribed pattern is a **one-message fan-out** — dispatch
  all investigate/critic/validate/patch subagents in a single message to
  maximize concurrency and prompt-cache reuse. `SKILL.md:190-191` admits "a
  transient 429/529 can wipe the whole batch, and agents write findings only
  when they finish, so mid-run crashes lose the batch's work." The mitigations
  (wave-batching to ~3-4, backoff, resume-by-agent-id, skip-terminal-candidates)
  are all prose the driving model is trusted to follow. There is no code
  semaphore, no retry wrapper, no batch checkpoint.
- Safe modification: In Go this is `errgroup` + a bounded semaphore + the
  official client's `max_retries`; findings are written per-agent as they land
  (payload-before-bookkeeping) so a batch crash loses at most one agent's work.
  The migration brief lists this as a gap that becomes free in code.
- Test coverage: None — the fan-out is not code, so nothing tests it.

**Prompt-cache prefix ordering is unverified against the current prompts:**
- Files: `agents/*.md`, `references/prompt-constants.md`.
- Why fragile: The migration brief's cache economics (context doc lines 109-134)
  require `[stable system + constants + KB]` FIRST, per-agent variable content
  (attack class, candidate partition) LAST. The current prompts substitute
  `{{ATTACK_CLASS}}` / `{{TARGET}}` / `{{WORKSPACE}}` inline (`SKILL.md:178`),
  and it has not been verified that no variable is interpolated ahead of the
  shared KB prefix. If a variable lands early, the shared prefix ends there and
  caching collapses — the dominant cost driver in fan-out.
- Safe modification: When porting prompts to Go, assemble messages as explicit
  ordered segments with a cache breakpoint after the stable prefix; assert no
  per-agent variable precedes it.
- Test coverage: None.

**No subprocess timeouts on any external tool call:**
- Files: `helpers/sec_harness/astgrep.py:65`, `codeql.py:213`/`:223`,
  `sca.py:97`, `structural_index.py:103`, `secrets.py`, `verify.py`,
  `rule_matcher.py`, `githist.py`, `profile.py`, `clsmap.py`, `redteam.py`,
  `repo_memory.py`, `diffscope.py` — every `subprocess.run` call.
- Why fragile: No `subprocess.run(...)` in the codebase passes `timeout=`. A hung
  semgrep/codeql/osv-scanner/rg on a pathological target blocks the whole scan
  indefinitely. `check=False` is used consistently (good — non-zero exits don't
  crash), and JSON parse errors are caught (`astgrep.py:71`, `sca.py:110`), but a
  hang has no guard.
- Safe modification: In Go, every `exec.CommandContext` gets a context deadline
  from the start. Add per-tool timeouts as a first-class config.
- Test coverage: Runners are dependency-injected for tests (`runner=subprocess.run`),
  so timeout behavior is untested by construction.

---

## The Non-Portable Piece

**The LLM-subagent seam has no Python implementation to port:**
- Files: `SKILL.md`, `agents/*.md` (the prompts), and the *absence* of any
  prompt-construction / API-calling / tool-dispatch code in `helpers/sec_harness/`.
- Problem: In the CC skill, the Claude Code harness IS the agent runner — it
  reads `SKILL.md`, spawns subagents via the Agent tool, provisions the Read/rg
  tools, and routes models. **None of that is in this repo.** There is no
  `anthropic` client call, no tool-loop, no `submit_findings` dispatcher, no
  message assembly anywhere in `helpers/sec_harness/`. The deterministic CLIs
  (`cli.py`, `astgrep.py`, `structural_index.py`, etc.) are the *tools* the
  agents call, but the code that *calls the model and hands it those tools*
  does not exist in Python.
- Impact: This is the one piece with zero port source. The Go build must write,
  from scratch: the agent-runner interface (migration doc layer 2), a raw
  Messages API tool loop with forced `tool_choice` for structured output,
  `cache_control` breakpoints, the 5 tool JSON schemas (`read_file`, `ripgrep`,
  `ast_grep`, `structural_index`, `submit_findings`) with READ-ONLY / no-network
  enforcement, and model routing. Everything else is a mechanical port against
  the 156/202-test golden oracle; this is genuine new construction.
- De-risk: The migration brief's build order A/B spikes this first (runner on one
  phase, then cache+fan-out measurement) precisely because it is the only
  unproven, non-ported surface.

---

## Portability Concerns (Python → Go, headless target)

**Install/preflight guidance is macOS/Homebrew-only:**
- Files: `helpers/sec_harness/preflight.py:26-35`.
- Issue: Every tool's `install_cmd` is a `brew install …` string. The stated Go
  goal is "runs headless — CI, container, CLI" and "one binary in distroless."
  Homebrew instructions are wrong for the distroless/Linux-CI target audience.
- Fix approach: The preflight logic (`check_tools` via `shutil.which` →
  `exec.LookPath`, plus the codeql per-language pack-cache check,
  `preflight.py:79-101`) ports cleanly and the migration brief correctly says it
  deletes the packaging risk. But the install-hint strings need Linux/container
  equivalents (or a package-manager-agnostic message).

**`__pycache__`, `.ruff_cache`, `.pytest_cache`, `.DS_Store`, and `err.log`
committed into the skill tree:**
- Files: `helpers/.ruff_cache/`, `helpers/.pytest_cache/`,
  `helpers/sec_harness/__pycache__/`, `agents/.DS_Store`, `helpers/.DS_Store`,
  `.ruff_cache/`, `helpers/err.log`.
- Issue: Build/editor artifacts are present in the tree. `err.log` (1 KB) in the
  helpers root is a stray artifact. Minor, but they pollute the "what to port"
  surface and the `__pycache__` dirs contain stale `.cpython-313`/`-314` bytecode
  for modules (e.g. `secrets`, `githist`) that could mislead a mechanical port
  tool into treating them as sources.
- Fix approach: Do not carry these into the Go repo; they are not port targets.

---

## Test Coverage Gaps

**Everything that is prose is untested by construction:**
- What's not tested: phase sequencing, fan-out concurrency/backoff, phase-
  completion contract, cache-prefix ordering, prompt-injection enveloping in the
  live pipeline, secret redaction in the live pipeline, subprocess timeouts.
- Files: the gaps trace to `SKILL.md` + `agents/*.md` (no code) and the orphaned
  `envelope.py`/`redactor.py`.
- Risk: The deterministic core has a strong golden oracle (156/202 tests) that
  makes its port a mechanical, checkable exercise. The orchestration + agent-
  runner + safety-enforcement layers have **no oracle** — they are exactly the
  layers being written new in Go, so the port cannot lean on existing tests
  there. The migration brief's eval harness (`helpers/bench/`, `BinaryAdapter`)
  is the intended regression oracle for the Go binary's *outputs*, but it grades
  findings, not orchestration internals.
- Priority: High for the runner/orchestrator (new code, no oracle); Medium for
  wiring the safety helpers (helpers are tested, only the call site is new).

---

*Concerns audit: 2026-07-30*
