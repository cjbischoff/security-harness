# security-harness

A self-contained, agentic **security-audit harness**. It runs bundled static analysis, drives
LLM investigation / adversarial-validation / patching agents over a per-repo knowledge base, and
emits SARIF + Markdown reports — grounding every confirmed finding in a mechanical tool receipt,
and never executing the target.

Today it ships as a **Claude Code skill** (`skills/sec-harness/`). A standalone **Go binary**
driven only by an Anthropic API key is the planned rewrite and will live in this same repo (see
*Roadmap*).

## What it does

- **Static-first, grounded.** Bundled SAST (Semgrep, CodeQL, OSV/SCA, secrets) prefilters
  candidates; LLM agents investigate per attack-class. A finding only reaches `confirmed` with at
  least one **mechanical tool receipt** — LLM reasoning alone never confirms.
- **Adversarial by default.** Every analysis/context phase is battle-tested by an independent
  adversary (opus, a different model family than the finder) before the next phase trusts it;
  findings run an FP-reduction ladder (critic → adversarial-validate → calibrate).
- **Static → runtime bridge.** A red-team phase splits confirmed findings into *static-settled*
  vs *needs-runtime* and hands a human a prioritized **manual runtime test plan** (`redteam-plan.md`)
  with shell-variable payloads. The harness itself still never runs anything.
- **Durable + resumable.** Per-repo memory keyed by repo identity, multi-pass campaigns, and a
  dev-only bench harness that measures precision/recall and locks regressions.

## Invariants

- **Never executes or modifies the reviewed source.** Static analysis only; patches apply
  to a throwaway copy — the repo's own source files are never run or edited.
- **Writes only its own sidecar.** Artifacts live in an in-repo, self-ignoring
  `<target>/.sec-harness/<slug>/` (override base `$SEC_HARNESS_HOME`, workspace `--workspace`).
- **Tool-receipt gate.** Only `semgrep`/`codeql`/`ast-grep`/`ripgrep`/`structural-index`/`secrets`/
  `sca` receipts can confirm a finding.
- **Untrusted repo content is data, not instructions.**

## Quick start

```bash
# Semgrep rules ship as a submodule — clone with it:
git clone --recurse-submodules <your-fork-url> security-harness
cd security-harness

# Deterministic core (Python, stdlib-only helpers):
cd skills/sec-harness/helpers
uv run python -m sec_harness.preflight        # check semgrep/codeql/ast-grep + query packs
uv run pytest -q                              # test suite
```

The operational playbook — phase order, agent prompts, and every `python -m sec_harness.<module>`
entrypoint — is in [`skills/sec-harness/SKILL.md`](skills/sec-harness/SKILL.md); the skill's own
[`README.md`](skills/sec-harness/README.md) has the full pipeline and feature detail.

## Layout

```
skills/sec-harness/
  SKILL.md                 operational playbook (phase order + per-phase detail)
  agents/                  LLM agent prompts (recon, threat-model, investigate, critic,
                           validate, trace, judge, patch, red-team, …)
  references/              attack-classes, prompt-constants, hunting knowledge, compliance corpora
  helpers/sec_harness/     deterministic Python core (SAST orchestration, gates, calibrate,
                           dedupe, verify, report, reachability, red-team, …)
  helpers/bench/           dev-only evaluation harness (precision/recall + regression)
  helpers/rules/semgrep/   → git submodule: github.com/semgrep/semgrep-rules
```

## Pipeline (per `SKILL.md`)

`preflight → context-ingest → recon / architecture / threat-model` (each adversary-gated)
`→ prefilter (semgrep + codeql + osv + secrets) → investigate (per class, gate ladder)`
`→ dedupe → critic → adversarial-validate → calibrate → patch → validate-fix → verify`
`→ red-team (static→runtime bridge) → report → postflight`.

## A note on the safety helpers

`envelope.wrap_untrusted` (untrusted-content envelope) and `redactor` / `verify_no_secrets`
(secret masking) are helpers the agent prompts instruct agents to use. Enforcement is
**prompt-level, not a hard code-path gate** — if you build a driver that feeds repo content to a
model directly, wire these in yourself for a real guarantee.

## Roadmap

- **Go rewrite** — a single binary driven by an Anthropic API key, with an optional sandboxed
  dynamic mode (execution-verify a candidate PoC). Design principles and the port target are
  tracked in the project's local design docs; the code will land in this repo.

## Develop

```bash
cd skills/sec-harness/helpers
uv run pytest -q
uv run ruff check sec_harness/ bench/ tests/
```

## License

No license is set yet — add one before publishing if you intend others to use it. Note the
Semgrep rules are a submodule under Semgrep's own license, not vendored here.
