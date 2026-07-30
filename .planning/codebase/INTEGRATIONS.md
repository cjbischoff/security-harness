# External Integrations

**Analysis Date:** 2026-07-30

**Scope:** `skills/sec-harness/`. All "integrations" here are local CLI binaries the harness shells out to and the LLM-subagent seam — there are no network APIs, databases, or cloud services in the core.

## External Tool Binaries (shelled out via `subprocess`)

Every backend is discovered with `shutil.which` and treated as optional; a missing tool is recorded as skipped rather than failing the run. The harness **never executes the scanned code** — all tools are static analyzers over source.

**SAST:**
- `semgrep` — primary pattern SAST across all languages.
  - Wired in: `helpers/sec_harness/sast.py` (`run_semgrep`) — invokes `semgrep --config <config> --json --no-git-ignore <target>`.
  - Rules: local `helpers/rules/smoke.yaml` + the vendored `helpers/rules/semgrep/` submodule (see below).
  - CLI entry: `helpers/sec_harness/cli.py` runs `run_semgrep -> normalize`.
- `codeql` — semantic dataflow/taint (`security-extended`), for compiled languages.
  - Wired in: `helpers/sec_harness/codeql.py` (`run_codeql`) — `codeql database create` then `codeql database analyze <lang>-queries`; parses SARIF (`parse_codeql_sarif`).
  - Safety gate: `codeql_config_trusted()` refuses untrusted `qlpack`/`.github/codeql` configs because `database create` compiles the target on the host.
  - Requires `codeql/<language>-queries` in the local pack cache (`~/.codeql/packages`).
- `ast-grep` (or `sg`) — structural pattern search.
  - Wired in: `helpers/sec_harness/astgrep.py` (`run_astgrep`, `astgrep_available`, `_binary`) — `--json` output, 0-indexed lines normalized to 1-indexed.

**SCA (dependency CVEs):**
- `osv-scanner` — scans lockfiles/manifests against the OSV database.
  - Wired in: `helpers/sec_harness/sca.py` (`run_sca`) — `osv-scanner --format json --recursive <target>`; raises `ScaError` when absent (caller records skipped). Note: exit 1 means "vulns found", not error.

**Secrets:**
- `gitleaks` — optional curated secret scanner.
  - Referenced in `helpers/sec_harness/secrets.py` as the recommended install for broad detection. The core itself ships only `password = "..."` regex + entropy heuristics; gitleaks is the documented upgrade seam, not a hard dependency.

**Search / grounding:**
- `rg` (ripgrep) — symbol lookup and evidence grounding.
  - Wired in: `helpers/sec_harness/structural_index.py` — `rg --no-heading --line-number --word-regexp <symbol> <root>`.
  - Also a first-class **evidence receipt type** alongside `semgrep`/`codeql`/`ast-grep`/`tree-sitter` (`helpers/sec_harness/evidence.py` `_MECHANICAL` set; `findings_gate.py`).

**Version control:**
- `git` — diff scope, history, novelty, per-repo memory, verification.
  - Wired in: `diffscope.py`, `githist.py`, `novelty.py`, `repo_memory.py`, `verify.py`.

**Coverage matrix:** `helpers/sec_harness/detection_coverage.py` documents the tool-to-language coverage grid (semgrep / codeql / osv-scanner / agent+ripgrep for SAST-blind languages like Liquid/templates).

## LLM / Anthropic Subagent Seam

**No LLM SDK is imported.** There is no `anthropic`/`openai`/`httpx` dependency anywhere in the core — the harness is stdlib-only. The "LLM" is the Claude Code / Agent session that hosts the skill.

- **Agents are markdown prompts**, not code: `agents/*.md` (recon, architecture, threat-model, investigate, critic, validate, redteam, patch, factcheck, judge, phase-adversary, etc.) and per-class prompts `agents/classes/{crypto,authz,config,injection,resource}.md`.
- **Driver contract** (`SKILL.md`): agent steps spawn a subagent with the named prompt (token substitution), model tier per step (sonnet for investigate, opus for adversary/critic). Deterministic steps run as `python -m sec_harness.<module>` and carry no LLM. Phases interleave: e.g. Prefilter (no LLM) → Investigate (sonnet, parallel per class) → Dedupe/Calibrate/Verify/Gate/Report (no LLM).
- **Evidence discipline:** mechanical tool receipts (semgrep/codeql/ast-grep/tree-sitter/ripgrep) yield HIGH confidence; bare LLM assertions are `llm-claimed` and must be grounded before they pass `findings_gate` (`helpers/sec_harness/evidence.py`, `findings_gate.py`).
- **Bench adapter seam:** `helpers/bench/adapter.py` — `WorkspaceAdapter` shells out to a standalone scanner binary (the Go migration target: `<argv> --target <repo> --workspace <ws>`); `CCSkillAdapter` is a documented placeholder that raises `NotImplementedError` — the CC skill is driven by an operator or a future Agent-SDK driver into a workspace, then graded via `WorkspaceAdapter`.

## Data Storage

- **Workspace filesystem only.** `helpers/sec_harness/workspace.py` + `state.py` manage a per-run workspace holding `findings/*.json`, `kb/`, `gates/`. No database, no cache service, no remote object store.
- **Per-repo memory:** `helpers/sec_harness/repo_memory.py` persists learnings keyed to the target repo (via `git`), on local disk.

## Authentication & Identity

- None in the core. External tool auth (e.g. `codeql pack download`, `osv-scanner` DB) is delegated to those tools' own configuration/caches; the harness does not read or store credentials.

## Monitoring & Observability

- **Error handling:** each backend raises a typed error (e.g. `ScaError`) or is skipped on absence; recorded in workspace state.
- **Logs:** plain stdout/stderr from the invoked binaries; no logging framework, no error-tracking service.

## CI/CD & Deployment

- None in scope. No hosting platform, no CI pipeline config under `skills/sec-harness/`. The harness runs locally as a Claude Code skill.

## Vendored Submodule

- **`helpers/rules/semgrep/`** — git submodule of `https://github.com/semgrep/semgrep-rules` (declared in repo-root `.gitmodules`). Upstream community/security rulesets consumed by `run_semgrep`. Out of scope for editing — treat as vendored input.

## Environment Configuration

- No required env vars in the core. Full-fidelity runs need the external binaries on `PATH`; each degrades gracefully when missing.

## Webhooks & Callbacks

- Incoming: none.
- Outgoing: none.

---

*Integration audit: 2026-07-30*
