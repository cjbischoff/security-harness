# security-harness (Go)

## What This Is

A standalone **Go** security-audit harness that runs an agentic, static-first vulnerability
audit of a codebase, driven only by an `ANTHROPIC_API_KEY` — no Claude Code, no plugins. It is a
port of the existing Python `sec-harness` skill (mapped in `.planning/codebase/`): the same
phase pipeline, tool-receipt grounding, adversarial validation, and red-team static→runtime
bridge, delivered as a single self-contained binary.

## Core Value

Produce **high-signal, tool-receipt-grounded, adversarially-validated** security findings (plus
a manual runtime test plan) from a single Go binary an operator points at a repo with an API
key — preserving the Python harness's invariants (never executes the target, only mechanical
receipts confirm) while removing the Claude Code dependency.

## Requirements

### Validated

<!-- Proven in the Python reference (see .planning/codebase/). These are the LOCKED behavioral
spec the port must preserve — not yet shipped in Go, so tracked as the target contract. -->

- ✓ Phase pipeline: preflight → context-ingest → recon → architecture → threat-model → prefilter
  → investigate → dedupe → critic → adversarial-validate → calibrate → patch → validate-fix →
  verify → red-team → report → postflight — *proven in Python*
- ✓ Tool-receipt gate: only mechanical receipts (semgrep/codeql/ast-grep/ripgrep/structural-index/
  secrets/sca) confirm a finding — *proven in Python*
- ✓ FP-reduction ladder (critic → adversarial-validate on a different model family → calibrate) —
  *proven in Python*
- ✓ Static-only invariants: never execute the target; patches apply to a throwaway copy; never
  write into the target repo — *proven in Python*
- ✓ Per-repo memory + resumable multi-pass campaigns; SARIF + Markdown report — *proven in Python*

### Active

<!-- The Go port. Building toward these. -->

- [ ] **Go deterministic core** — port the ~50-module Python core (Finding schema/models,
  workspace/KB, prefilter SAST orchestration, gates, dedupe, calibrate, verify, report/SARIF,
  reachability, red-team, phase_gate, context C1/C2, campaign/memory) with parity tests.
- [ ] **Anthropic tool-loop seam** — the one piece with NO Python source: a raw Messages API
  client + thin agentic tool-loop behind a single interface (forced `tool_choice`, prompt
  caching, ret/backoff), so the rest of the port is provider-agnostic.
- [ ] **Agent prompt port** — recon / architecture / threat-model / context-ingest / investigate
  / critic / adversarial-validate / trace / judge / patch / validate-fix / red-team prompts,
  preserving the tool-receipt gate and different-family adversary discipline.
- [ ] **The 5 tools** the agent loop exposes (read, grep/ripgrep, ast-grep, structural-index,
  write-to-throwaway) — sandboxed to read-only over the target.
- [ ] **Single-binary CLI + preflight** — `--target` + `ANTHROPIC_API_KEY`; preflight checks the
  assumed-installed binaries (semgrep, codeql, ast-grep, osv-scanner, gitleaks, git) and fails
  loud on gaps; cross-platform (not macOS/Homebrew-only).
- [ ] **Native tree-sitter call-graph indexer (F4)** — replaces the rg-based structural index;
  fixes PHP/OO reachability precision; emits `tree-sitter:*` receipts.
- [ ] **Eval/bench parity harness** — port the Layer A/B/C bench as the golden oracle; Go output
  must match the Python reference on shared fixtures (precision/recall + regression).
- [ ] **Reliability primitives** — subprocess timeouts everywhere, checkpoint idempotence +
  salvage, provider-load (429/529) backoff — the "free in code" robustness the migration doc lists.

### Out of Scope

- **Sandboxed dynamic runtime mode (Bucket D)** — the optional gVisor/two-container execution-
  verify path is a v2 target; v1 stays static-only + emits the manual runtime plan. *(Deferred —
  large, needs a Linux+gVisor host; the red-team bridge already hands humans the plan.)*
- **Vendoring third-party rules** — Semgrep rules stay a submodule; not re-hosted. *(Licensing +
  bloat.)*
- **Any Claude Code / plugin dependency** — the whole point is a self-contained binary. *(Removing
  the current substrate is the project.)*
- **Rewriting the audit methodology** — the pipeline, gates, and prompts are ported, not
  redesigned. *(The Python reference is the spec.)*

## Context

- **Reference implementation:** the Python `sec-harness` under `skills/sec-harness/`, fully mapped
  in `.planning/codebase/` (STACK, ARCHITECTURE, STRUCTURE, CONVENTIONS, TESTING, INTEGRATIONS,
  CONCERNS) and designed for this port in `docs/sec-harness-go-migration-context.md`.
- **The core new work is the orchestrator + the LLM tool-loop:** the map confirms orchestration
  currently lives in `SKILL.md` prose and the subagent tool-loop has no Python source — both are
  written fresh in Go. The deterministic modules are a mechanical port.
- **Golden oracle:** the existing Python bench + test fixtures give a parity target so the Go port
  can be verified against known-good behavior.
- **Known reference concerns to fix in the port:** no subprocess timeouts; envelope/redactor were
  prompt-level only (make them real code gates in Go); rg-based structural index (→ tree-sitter);
  macOS-only preflight hints.

## Constraints

- **Tech stack**: Go (single static binary). Substrate = raw Anthropic Messages API + a thin tool
  loop behind one seam — *chosen for portability + no SDK lock-in (migration doc §substrate).*
- **Security**: never execute the target; only mechanical tool receipts confirm findings;
  untrusted repo content is data, not instructions — *these invariants are non-negotiable.*
- **Dependencies**: external analysis binaries (semgrep/codeql/ast-grep/osv/gitleaks/git) are
  assumed-installed + preflight-checked, not vendored — *packaging risk deleted (migration doc).*
- **Driver**: an `ANTHROPIC_API_KEY` is the only required credential — *no Claude Code runtime.*

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Language: Go, single binary | Portable, self-contained, no Python runtime; distroless/CI-friendly | — Pending |
| Substrate: raw Messages API + thin tool-loop behind one seam | Avoid SDK lock-in; isolate the only provider-coupled code | — Pending |
| Binaries assumed-installed + preflight-checked | Deletes packaging risk vs vendoring SAST tools | — Pending |
| Golden-oracle parity vs the Python bench | Port correctness is verifiable against known-good behavior | — Pending |
| Sandboxed dynamic mode deferred to v2 | Large + host-constrained; static bridge already ships a manual plan | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-07-30 after initialization + codebase mapping*
