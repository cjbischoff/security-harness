# Technology Stack

**Analysis Date:** 2026-07-30

**Scope:** `skills/sec-harness/` — the Python sec-harness (`helpers/sec_harness/` deterministic core, `helpers/bench/`, `agents/`, `references/`). Excludes `reference_tools/`, `test_repos/`, `docs/`, and the `helpers/rules/semgrep/` git submodule (upstream, not our code).

## Languages

**Primary:**
- Python 3.12+ (`requires-python = ">=3.12"` in `helpers/pyproject.toml`) — the entire deterministic core under `helpers/sec_harness/` (~5,900 LOC across ~55 modules) and the eval harness under `helpers/bench/`.

**Secondary:**
- Markdown — agent prompts under `agents/*.md` and `agents/classes/*.md` are the LLM subagent seam (not executable code; consumed by the driver). Reference policy/config under `references/` (`.md`, `.yaml`, `.schema.json`).
- YAML / JSON Schema — `references/*.yaml` (approved crypto algorithms, key sources, scan/fix schemas), `helpers/rules/smoke.yaml` (local semgrep smoke ruleset).

## Runtime

**Environment:**
- CPython 3.12+. The core is **standard-library only at runtime** — no third-party runtime packages (`dependencies = []` in `helpers/pyproject.toml`). Uses `subprocess`, `shutil.which`, `json`, `argparse`, `pathlib`, `dataclasses`.

**Package Manager:**
- `uv` (dev-groups syntax `[dependency-groups]` in `helpers/pyproject.toml`).
- Build backend: `hatchling`; wheel packages `sec_harness`.
- Lockfile: not detected in scope (no `uv.lock` under `helpers/`).

## Frameworks

**Core:**
- None. Intentionally framework-free; the design constraint is zero runtime dependencies so the harness is self-contained and portable (this Python impl is the reference for a planned Go rewrite — see `docs/sec-harness-go-migration-context.md`).

**Testing:**
- `pytest>=8` (dev group). Config: `[tool.pytest.ini_options] testpaths = ["tests"]` in `helpers/pyproject.toml`.

**Build/Dev:**
- `ruff>=0.6` — lint + format. Config in `helpers/pyproject.toml`: `line-length = 100`, `target-version = "py312"`, excludes `fixtures`/`rules`, per-file ignore `E702` for tests.
- `ty>=0.0.1a1` — type checker (Astral, pre-release). Excludes `fixtures`/`rules`.

## Key Dependencies

**Critical:**
- None at runtime (by design).

**Infrastructure (external binaries shelled out at runtime — not Python packages):**
- `semgrep` — primary SAST backend (`helpers/sec_harness/sast.py`).
- `codeql` — semantic dataflow/taint (`helpers/sec_harness/codeql.py`).
- `ast-grep` / `sg` — structural search (`helpers/sec_harness/astgrep.py`).
- `osv-scanner` — dependency CVE / SCA (`helpers/sec_harness/sca.py`).
- `rg` (ripgrep) — symbol/grounding search (`helpers/sec_harness/structural_index.py`).
- `git` — history/diff/novelty (`diffscope.py`, `githist.py`, `novelty.py`, `repo_memory.py`, `verify.py`).
- `gitleaks` — optional curated secret scanner (referenced as install target in `helpers/sec_harness/secrets.py`; core ships only regex/entropy heuristics).

All binaries are gated behind `shutil.which` checks; absence is recorded as "skipped", never a crash. See INTEGRATIONS.md.

## Configuration

**Environment:**
- No env-var-based runtime config in the core. Behavior is driven by workspace state (`sec_harness.workspace`/`state`) and reference policy files under `references/`.

**Build:**
- `helpers/pyproject.toml` — single source for build, lint, type, and test config.

## Platform Requirements

**Development:**
- Python 3.12+, `uv`, and the external scanner binaries on `PATH` for full-fidelity runs (each is independently optional/skippable).

**Production:**
- Runs as a Claude Code skill: deterministic Python steps invoked via `python -m sec_harness.<module>`; agentic phases run as subagents inside a Claude Code / Agent session (not a standalone daemon). No hosting/deploy target — it executes locally against a checked-out target repo and never runs the scanned code.

---

*Stack analysis: 2026-07-30*
