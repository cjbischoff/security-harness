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

<!-- entries appended below -->
