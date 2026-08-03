# sec-harness runtime-issues log — 2026-08-03

Observations from the instrumented dogfooding run. Each entry: phase, repo,
severity (`blocker` / `correctness` / `data-quality` / `efficiency` /
`wasted-effort`), evidence, and proposed fix. Blockers fixed inline on
`skill-dogfood-fixes-20260803`; the rest await triage.

| # | phase | repo | severity | summary | status |
|---|-------|------|----------|---------|--------|
| 001 | T1 graph build | ai-platform | efficiency (blocking scale) | O(symbols×names) call-edge loop with fresh regex per pair; 270s on 268 files | FIXED inline (7463245) |
| 002 | C1 context-ingest | ai-platform | correctness | `Workspace('<str>')` in agent prompts throws TypeError; guaranteed first-run failure | FIXED inline (da058dc) |
| 003 | C1 context-ingest | ai-platform | data-quality (prompt) | context-ingest prompt assumes narrative docs; thin structural docs (dir tree + comments) under-specified — agent had to infer "follow dir-comment breadcrumbs into impl files" | BATCHED (prompt clarify) |
| 004 | Recon | ai-platform | data-quality (wiring) | recon.md never references kb/context.json; C1 leads silently unused by recon unless orchestrator injects them | BATCHED (prompt wiring) |
| 005 | Recon | ai-platform | data-quality (ref doc) | ai-agent hunting-doc class list reads as "select the whole bundle"; nearly inflated scope with unearned mcp-trust-inheritance | BATCHED (doc clarify) |
| 006 | Recon phase-gate | ai-platform | data-quality (gate coverage) | recon gate emits only entrypoint+subsystem claims; attack_surface/agents_to_spawn overreach not systematically challenged by the adversary | BATCHED |
| 007 | Recon | ai-platform | correctness (recall/waste) | recon cites plausible-but-nonexistent symbol names (main/authenticate/applyGuardrail); file:line gate passes at file granularity, so investigate is sent to a symbol that isn't there | BATCHED |
| 008 | Architecture/TM phase-gate | ai-platform | data-quality (missing wiring) | no claim-extractor for free-text architecture.md/THREAT_MODEL.md; phase_gate only has claims_from_profile/context. Naive path extraction over-produces (74 existence-claims) and false-rejects prose basenames (43) | BATCHED |
| 009 | Architecture | ai-platform | environmental (behavior) | subagent self-censored the Write of `entities/summary-and-persistence.md` ("subagents should return findings as text, not write report files") and renamed; risk = an agent returns text instead of writing a KB artifact (data loss) | BATCHED (dispatch-hardening) |

## Detail

### ISSUE-001 — Tier-1 graph call-edge detection is quadratic — FIXED
- **Phase:** T1 graph build (`sec_harness.graph.build_tier1`, graph.py:176-186).
- **Repo:** ai-platform (268 source files, 3877 symbols, 1362 unique names).
- **Severity:** efficiency; effectively blocking the multi-repo plan (larger
  repos would take far longer — cost scales O(symbols×unique_names)).
- **Evidence:** measured baseline **270.16s** to build the Tier-1 graph on
  ai-platform. Inner loop ran `re.search(r"\b"+re.escape(name)+r"\s*\(", body)`
  for every (body × known-name) pair = 5,280,474 iterations, each recompiling a
  regex (1362 distinct patterns thrash Python's 512-entry re cache).
- **Fix:** per body, collect the called \w-tokens once via one
  `re.finditer(r"\b(\w+)\s*\(")`; for purely-\w names use O(1) set membership
  (provably equivalent to the per-name regex); odd names (JS `$foo`) keep a
  precompiled pattern. Same edges, same append order → byte-identical
  `graph.json` (2,510,061 bytes, 7308 edges unchanged). **270s → 2.0s (~134×).**
- **Contract:** graph.json output unchanged, so Go parity is preserved exactly;
  no goldens to regenerate. Characterization test added
  (`test_call_edges_respect_word_boundary_and_substrings`).

### ISSUE-002 — `Workspace('<str>')` throws TypeError — FIXED
- **Phase:** C1 context-ingest (recurs in any agent command copying the pattern).
- **Evidence:** `sec_harness.workspace.Workspace` is a dataclass typed `root: Path`
  with no coercion; `Workspace('/path')` then does `str / "kb"` →
  `TypeError: unsupported operand type(s) for /: 'str' and 'str'`. The
  `context-ingest.md:39` example command passes a bare string, so it is a
  guaranteed first-run failure; the subagent had to wrap in `Path(...)`.
- **Fix:** `__post_init__` coerces `root` + the three optional override paths to
  `Path`. Behavior-preserving for existing Path callers (idempotent). Prevents
  wasted retries across the remaining agent phases.

### ISSUE-003 — context-ingest prompt assumes narrative docs — BATCHED
- **Phase:** C1. `discover_context_files` returned only an auto-generated
  `docs/project-structure.md` (dir tree + one-line `#` comments). The prompt's
  "extract claims / ground `where` in real paths" procedure assumes prose
  security docs. The agent correctly inferred it should follow directory-comment
  breadcrumbs into implementation files and verify there, but the prompt does not
  say so. **Proposed:** add a line to `context-ingest.md` that thin/structural
  docs are expected and comment breadcrumbs should be followed into real modules
  (absence of narrative docs ≠ "nothing to extract"). Prompt-only; batched.
- **Note:** C1 still produced real signal here — CTL-0001, a fail-open Bedrock
  guardrail (`guardrail.ts:126,169-176`), which is a legitimate lead.

### ISSUE-006 — recon phase-gate doesn't challenge attack-class overreach — BATCHED
- `phase_gate.claims_from_profile` emits one claim per entrypoint + subsystem, but
  NOT per `attack_surface`/`agents_to_spawn` class. So the opus adversary's 26-row
  table never systematically challenges "is this attack class justified by a code
  indicator?" — the exact overreach recon is most prone to. It was only checked
  here because the orchestrator dispatch added an ad-hoc instruction.
- **Proposed:** emit attack-class claims too (each with the indicator ref recon
  used), or add a profile-level overreach step to `phase-adversary.md`. Medium value.

### ISSUE-007 — recon emits nonexistent symbol names (file resolves, symbol doesn't) — BATCHED
- 3 of 4 WEAKENED verdicts were recon citing a plausible symbol that does not exist
  (`index.ts:main`, `authentication.middleware.ts:authenticate`,
  `bedrock-guardrail…:applyGuardrail`). `phase_gate.ref_resolves` checks file (and
  line range) but not that the symbol after `:` exists, so these pass the
  deterministic gate and would send an investigate agent to a nonexistent symbol =
  wasted effort / degraded navigation.
- **Proposed:** a recon-time (or gate-time) check that an entrypoint's `:symbol`
  resolves via the structural index / graph symbol nodes, not just the file.
  Medium value; ties into the graph symbol_at helper already present.

### ISSUE-008 — no principled claim-extractor for architecture/threat-model gates — BATCHED
- `phase_gate` provides `claims_from_profile` and `claims_from_context`, but the
  architecture and threat-model artifacts are free-text Markdown. SKILL.md says
  each ends in a phase gate, and `phase-adversary.md` lists them as reviewable, yet
  nothing turns their content into `{id,text,refs}` claims. The orchestrator must
  hand-roll extraction.
- Observed both failure modes of naive extraction on ai-platform's `architecture.md`:
  pulling every `*.ts` token produced **117 refs, 43 false "rejects"** (all bare
  basenames mentioned in prose, e.g. `chat.controller.ts` without its `src/`
  path); restricting to citation-form (path containing `/`) gave **74 refs, 0
  rejects** — but 74 low-value "this file exists" claims, not the ~10 load-bearing
  security assertions (trust boundaries, data-flow sinks, fail-open, HITL-empty)
  the adversary should actually challenge. **Corroborated by the opus adversary:**
  the deterministic gate only checks ref-resolvability (all 74 resolved) and never
  tests whether the prose *claim about* each ref is true — a weak gate for free-text
  phases. The adversary had to be scoped by the orchestrator to load-bearing
  assertions; without that it would emit 74 noise rows.
- **Proposed:** a `claims_from_architecture` / `claims_from_threat_model` that
  extracts the *asserted security claims* (section headers + their cited refs),
  not raw path mentions; only count citation-form refs for the deterministic
  reject check. Medium-high value — it's what makes the earlier phase gates real.

### ISSUE-009 — subagent avoids writing "report/summary"-named KB artifacts — BATCHED
- The architecture subagent tried to write `kb/entities/summary-and-persistence.md`
  and reported the Write was refused as "subagents should return findings as text,
  not write report files"; it renamed to `persistence-layer.md` and wrote it
  (content intact — no loss THIS time). Root cause is not sec-harness code and not
  the `agent-flow/hook.js` telemetry hook (83 lines, forwards events only) — it is
  the subagent self-censoring on a report/summary-like filename.
- **Risk:** a future agent could return the artifact as chat text instead of
  writing it → silent KB gap. The harness's whole design has agents write KB files.
- **Proposed (dispatch-hardening, applied for the rest of this run):** every agent
  dispatch states explicitly that writing the named KB artifact to the given path
  IS the task and is expected, overriding any "don't write report files" instinct.
  Longer-term: the agent prompts themselves should carry that assertion.

<!-- entries appended below -->
