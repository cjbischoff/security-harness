# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A self-contained agentic **security-audit harness**: bundled SAST (Semgrep, CodeQL, OSV/SCA, secrets)
prefilters candidates, LLM agents investigate per attack-class over a per-repo knowledge base, and
SARIF + Markdown reports are emitted. It **never executes or modifies the reviewed source**.

## Two workstreams — know which one you are

This repo is developed by two parallel processes with an **absolute boundary**:

| Path | Workstream | Authoritative guide |
|------|-----------|---------------------|
| `skills/sec-harness/` | The shipping skill (Python core + agent prompts) — running audits & maintaining the skill | **`skills/sec-harness/CLAUDE.md`** (operating manual) + `skills/sec-harness/SKILL.md` (playbook) |
| `go/` | The Go binary rewrite — single binary driven by an Anthropic API key | `go/` package docs |

**If you are working in `skills/`, read `skills/sec-harness/CLAUDE.md` first** — it is the detailed
driver for the audit pipeline, the git protocol, and skill conventions. This root file is only the map.

## Git boundary (protects the parallel conversion)

- Touch only files in **your** workstream's path. Never edit, stage, or commit the other's tree.
- **Never `git add -A` / `git add .` / `git commit -a`** — stage explicit paths and `git status`
  before committing to confirm nothing from the other workstream is staged.
- Work on a branch; never commit to `main`. Merge via PR with user approval.

## The one coupling point — the JSON contract

The Go port mirrors the Python data contract **byte-for-byte**. `go/bench/gen_golden.py` writes
`json.dumps(obj.to_dict(), indent=2)` goldens from `sec_harness.models` into
`go/internal/model/testdata/`; Go's `TestParity` asserts byte-equality. **Python is the source of
truth.** The frozen files are `helpers/sec_harness/models.py` (Finding/CampaignState serialization;
`needs-deployment-testing` is hyphenated) and `helpers/sec_harness/evidence.py` (`_MECHANICAL`
tool-receipt whitelist). Changing either breaks the Go build — coordinate before touching them, and
regenerate goldens (`python3 go/bench/gen_golden.py`, which writes under `go/`).

## Commands

Python core — from `skills/sec-harness/helpers/`:

```bash
uv run pytest -q                                   # full suite (3 env-only failures; see skill CLAUDE.md §2)
uv run pytest tests/test_x.py::test_name           # single test
uv run ruff check sec_harness/ bench/ tests/       # lint (line-length 100)
uv run ty check                                    # static types
uv run python -m sec_harness.preflight             # verify SAST tooling + CodeQL packs
git submodule update --init --recursive            # check out the semgrep rules submodule
```

Go binary — from `go/`: `go test ./... -race`.

## Conventions

- The Python core is **stdlib-only** — no runtime dependencies (dev deps: pytest, ruff, ty).
- **Semgrep rules are a git submodule** (`helpers/rules/semgrep/`). Clone with `--recurse-submodules`.
- `docs/`, `.planning/`, `test_repos/`, `reference_tools/`, and bench corpus seeds are gitignored and
  never published (external code / confirmed vulns in private code).
