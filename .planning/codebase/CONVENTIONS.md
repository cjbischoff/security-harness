# Coding Conventions

**Analysis Date:** 2026-07-30

**Scope:** `skills/sec-harness/` only. This is the Python reference implementation of the sec-harness deterministic core; it exists to be re-implemented in Go. Map the Python reality so the Go port preserves the same contracts.

## Naming Patterns

**Files:**
- Module names are single lowercase nouns matching their domain: `prefilter.py`, `evidence.py`, `findings_gate.py`, `workspace.py`, `sast.py`, `codeql.py`, `sca.py`, `secrets.py`. Multi-word modules use snake_case (`fix_disposition.py`, `repo_memory.py`, `structural_index.py`, `crypto_policy.py`, `detection_coverage.py`).
- Package: `sec_harness/` (snake_case, the import root). Dev-only eval harness lives in a sibling package `bench/`.

**Functions:**
- snake_case verbs: `run_prefilter`, `parse_semgrep_json`, `validate_findings`, `run_semgrep`, `confidence_for`, `is_tool_receipt`.
- `run_*` = executes a backend/pipeline stage. `parse_*` = maps external tool output to models. `validate_*` = returns an error-list gate. `*_for` / `is_*` = pure predicates.
- Private helpers are prefixed `_` (e.g. `_cand`, `_profile`, `_json_blocks` in tests; module-level constants like `_SEMGREP_SEVERITY`, `_MECHANICAL`).

**Variables:**
- snake_case. Short local names in tight scopes (`ws`, `res`, `f`, `p`, `sem`, `cql`), full descriptive names elsewhere.

**Types:**
- PascalCase for dataclasses and enums: `Finding`, `CampaignState`, `ScanProfile`, `Workspace`, `Severity`, `FindingStatus`, `Confidence`.
- Enum members UPPER_SNAKE with lowercase string values: `Severity.HIGH = "high"`, `FindingStatus.NEEDS_DEPLOYMENT_TESTING = "needs-deployment-testing"`.

## Code Style

**Formatting:**
- `ruff` (dev dependency `ruff>=0.6`), configured in `skills/sec-harness/helpers/pyproject.toml`.
- `line-length = 100`, `target-version = "py312"`.
- `extend-exclude = ["fixtures", "rules"]` — fixtures and the semgrep-rules submodule are never linted.

**Linting:**
- `[tool.ruff.lint.per-file-ignores]` relaxes `E702` (multiple statements on one line, semicolon) for `tests/**` only — production code stays one-statement-per-line. Tests use `ws = Workspace(tmp_path); ws.ensure()` style.

**Type checking:**
- `ty` (Astral's type checker, dev dependency `ty>=0.0.1a1`). `[tool.ty.src] exclude = ["fixtures", "rules"]`.

**Python baseline:**
- `requires-python = ">=3.12"`. No runtime dependencies (`dependencies = []`) — the core is stdlib-only by design.

## Import Organization

**Order (observed, ruff-enforced isort grouping):**
1. `from __future__ import annotations` — first line of every production module, immediately after the module docstring.
2. Standard library: `import json`, `import subprocess`, `import argparse`, `from pathlib import Path`, `from dataclasses import ...`, `from enum import Enum`, `from concurrent.futures import ThreadPoolExecutor`.
3. First-party absolute imports: `from sec_harness.models import Finding, FindingStatus, Severity`.

**Path aliases:**
- None. All intra-package imports are absolute from the `sec_harness.` (or `bench.`) root — never relative (`from .models import`). The Go port should mirror this with a flat package layout.

## Error Handling

**Deterministic helpers return error-lists, not exceptions.**
- Validation/gate functions return `list[str]` of human-readable problems; empty list means pass. See `validate_findings(ws) -> list[str]` in `sec_harness/findings_gate.py:14` returning `"<id>: <problem>"` strings. Same pattern across `stage_validate.py`, `diffscope.py`, `profile.py`, `campaign.py`, `context.py`, `githist.py`, `redactor.py`, `factcheck.py`, `fix_disposition.py`.
- This keeps gates composable and side-effect-free; callers decide whether a non-empty list is fatal.

**Fail-open parsing.**
- External-tool output that fails to parse degrades gracefully rather than crashing the pipeline. `sec_harness/parse.py:27` catches `(json.JSONDecodeError, ValueError)`; `sec_harness/astgrep.py:71` catches `json.JSONDecodeError`; `sec_harness/sca.py:110` catches `json.JSONDecodeError`. A malformed backend result yields empty/partial findings, never an aborted scan.
- Contrast: real backend *failures* (a CodeQL build error) are surfaced explicitly via a typed exception (`CodeQLError`) that the orchestrator records in a `failed` list — a broken scan must be distinguishable from a clean one (`run_prefilter` docstring, `sec_harness/prefilter.py:37`). Fail-open is for parse noise; fail-loud is for backend breakage.

**Typed domain exceptions.**
- Backends raise their own error types (`CodeQLError`, `ScaError`) so the orchestrator can catch and record per-backend rather than swallowing.

## Injectable Runners (testability seam)

Every function that shells out or touches the environment takes its side-effecting dependency as a keyword-only injectable with a real default. This is the central testability convention.

- `run_semgrep(target, config, *, runner=subprocess.run)` — `sec_harness/sast.py:49`.
- `run_prefilter(ws, target, profile, *, semgrep=run_semgrep, codeql=run_codeql, has_tool=shutil.which, trust_fn=..., qlpack_fn=..., secrets_fn=..., sca_fn=..., exclusions_fn=..., max_workers=None)` — `sec_harness/prefilter.py:22`.
- Tests pass lambdas/stubs (`sem = lambda target, config, **k: [...]`) and assert a backend was *not* called by injecting a throwing stub (`lambda *a, **k: (_ for _ in ()).throw(AssertionError(...))`). See `tests/test_prefilter.py:41`.
- The `*` forces all seams keyword-only, so the positional signature stays the production call shape.

## Determinism

- The core is a "deterministic core" (pyproject description). Outputs must be byte-identical across serial and concurrent runs.
- Merged findings are sorted by a total key `(file, line, rule_id)` and re-assigned fresh contiguous `C-####` ids before persistence (`run_prefilter` docstring). `ThreadPoolExecutor.map` preserves submission order; the unit list is built deterministically so thread scheduling never affects output.

## Evidence Namespacing (a load-bearing convention)

Tool receipts must never be confused with LLM assertions. Enforced in `sec_harness/evidence.py`.
- Mechanical sources: `{"semgrep", "codeql", "ast-grep", "tree-sitter", "ripgrep", "structural-index", "secrets", "sca"}` — `evidence.py:14`.
- `evidence_sources` entries are namespaced `"<tool>:<detail>"`, e.g. `f"semgrep:{check_id}"` (`sast.py:43`), `codeql:dataflow`.
- LLM assertions are forced into the `llm-claimed:` namespace by `as_llm_claim()` so `is_tool_receipt()` rejects them (`evidence.py:35-37`, `40-49`).
- Confidence is the strongest link in the chain: any real receipt → `HIGH`; `llm-corroborated` → `MEDIUM`; else `LOW` (`confidence_for`, `evidence.py:52`).

## Models

- Domain models are `@dataclass` (not dicts, not Pydantic — stdlib only). `Finding` and `CampaignState` in `sec_harness/models.py`.
- Mutable defaults use `field(default_factory=list/dict)`; optional fields are `X | None = None`.
- Every model carries a `to_dict()` / `from_dict(cls, d)` pair. `to_dict()` converts enums to their `.value`; `from_dict()` is **forward-compatible** — it drops keys not in `cls.__dataclass_fields__` so a newer-schema finding loads under an older reader (`models.py:112-129`). The Go port must preserve this tolerant-read behavior.
- Enums subclass `(str, Enum)` so they serialize as plain strings and compare to string literals.

## Comments & Docstrings

- **Full Google-style docstrings on every public module, function, class, and dataclass** — `Args:`, `Returns:`, `Raises:`, attribute tables. See the `Finding` dataclass docstring (`models.py:42-81`) and `run_prefilter` (`prefilter.py:37-76`). This is a hard project rule, not optional.
- Module docstrings state the module's single responsibility in one or two sentences (`sast.py:1`, `evidence.py:1`, `findings_gate.py:1`).
- Inline comments explain *why*, often citing the bug or reference tool a decision came from ("this also fixes a latent bug where...", "Adapted from raptor's evidence_grade"). Seeded-vulnerability markers in fixtures are explicit (`# SQL injection (seeded vuln)`).

## Function Design

- Small, single-purpose functions. Pure parsers (`parse_semgrep_json`) are separated from the I/O wrapper that calls them (`run_semgrep`), so parsing is unit-testable without a subprocess.
- Keyword-only (`*`) for injectable seams and optional tuning knobs; positional for the core domain arguments.
- Return concrete types (`list[Finding]`, `list[str]`, `dict`) with the shape documented in the docstring's `Returns:`.

## Module Design

- Flat package: all modules directly under `sec_harness/`, no sub-packages. One module = one pipeline stage or one concern.
- `__init__.py` is minimal (package marker). No barrel re-exports — importers name the module: `from sec_harness.evidence import is_tool_receipt`.
- The CLI (`sec_harness/cli.py`) is the composition root: `argparse` subcommands wire stages together; individual stage modules never call `sys.argv` or exit.

---

*Convention analysis: 2026-07-30*
