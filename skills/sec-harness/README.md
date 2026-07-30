# sec-harness

A self-contained, agentic **security-audit harness**. It runs bundled SAST, drives
LLM investigation/validation/patching agents over a knowledge base, and emits SARIF +
Markdown reports with a citable compliance dimension — grounding every confirmed finding
in a mechanical tool receipt.

## Invariants

These hold everywhere and are enforced (in code where possible, prompt otherwise):

- **Never executes or modifies the reviewed source.** Static analysis only; patches
  apply to a throwaway copy — the repo's own source files are never run or edited.
- **Writes only its own sidecar.** Scan artifacts live in an in-repo, self-ignoring
  `<target>/.sec-harness/<slug>/` dir (override the base with `$SEC_HARNESS_HOME`, or
  the whole workspace with `--workspace`). A seeded `.sec-harness/.gitignore` keeps that
  output out of the repo's git tree.
- **Tool-receipt gate.** A finding can only reach `confirmed` with ≥1 mechanical receipt
  (`semgrep`/`codeql`/`ast-grep`/`ripgrep`/`structural-index`/`secrets`/`sca`). LLM
  reasoning alone (`llm-claimed:*`) can corroborate but never confirm. Enforced in
  `findings_gate`.
- **Signal over noise.** Adversarial validation (opus, different model family than the
  sonnet finder), an FP-reduction ladder, and a `needs-deployment-testing` verdict for
  bugs unprovable from source keep false positives out of the report.

## Layout

```
SKILL.md                     the operational playbook (phase order + per-phase detail)
agents/                      LLM agent prompts: recon, architecture, threat-model,
                             investigate, critic, validate (opus), patch, validate-fix,
                             factcheck, tune-config; classes/ (CWE-class fix extensions)
references/                  attack-classes.md, prompt-constants.md, finding-template.md,
                             hunting/ (domain knowledge), asvs/ + codeguard/ (compliance
                             corpora), approved-crypto-*.yaml, DETECTION_COVERAGE.md, schemas
helpers/sec_harness/         the deterministic Python core (46 modules)
helpers/bench/               dev-only evaluation harness (not part of a scan)
helpers/tests/               242 pytest tests
```

## Pipeline (per SKILL.md)

0. **Preflight** — `python -m sec_harness.preflight` (checks semgrep/codeql/ast-grep +
   per-language CodeQL query packs + optional osv-scanner/gitleaks; lists what's missing).
1. **Begin pass** — `from sec_harness.state import begin_pass`.
1.5 **Context-ingest (C1)** — `agents/context-ingest.md` distills the repo's OWN docs
   (`docs/`, `openspec/`, ADRs, `SECURITY*`, runbooks, prior review notes) **and** prior
   scans into `kb/context.json`, trust-tagged. It DRIVES the scan: trust boundaries +
   claimed controls → threat-model hunt rows. **C1 verifies now:** each claimed control gets
   a `verify_status` (PRESENT/MISSING/BYPASSABLE) vs code; MISSING/BYPASSABLE → `CTL-####`
   CANDIDATE findings (`context.control_findings`, `llm-claimed` evidence — can't confirm on
   doc text). `agents/context-adversary.md` (opus) pressure-checks that verification. Repo
   docs are untrusted claims — they never suppress or auto-confirm a finding.
2–4. **Recon → Architecture → Threat model** (sonnet agents) — build the KB
   (`scan-profile.json`, `architecture.md`, `entities/`, `THREAT_MODEL.md`). **Each ends with a
   phase adversary gate** (`agents/phase-adversary.md`, opus): deterministic ref-resolution
   pre-check → independent challenge of the analysis before later phases trust it
   (`sec_harness.phase_gate`, audit record in `kb/gates/<phase>.json`).
5. **Prefilter** (no LLM) — `run_prefilter` runs semgrep + codeql + osv-scanner (SCA) +
   secrets concurrently; classifies via `clsmap`; **never-silent** (any declared backend
   that doesn't run is recorded). Optional ASVS/CodeGuard `rule_matcher` pre-filter.
6. **Investigate** (sonnet, parallel per class) — gate ladder (−1 sanity … 3 new
   capability); confirmed → `raw`.
7–10. **FP ladder** — dedupe → critic → **adversarial-validate (opus)** → calibrate.
   Citations (ASVS/CodeGuard) auto-attach at calibrate.
10.5 **Fact-check** (F8) — a fresh agent re-verifies each written finding's citations/
   scope/severity against source.
11–14. **Patch (opus) → validate-fix → verify (no LLM) → report** — verify applies the
   patch to a copy, re-scans, and matches the finding's own rule.
14.5 **Red Team (static→runtime bridge)** — `agents/redteam.md` classifies each confirmed
   finding `static-settled` vs `needs-runtime` and writes a `runtime_test` (payloads with
   `$SHELL_VARS`); `agents/redteam-adversary.md` (opus) pressure-checks the plan;
   `python -m sec_harness.redteam` renders `redteam-plan.md` (only findings ≥ the confidence
   bar). The harness never executes — it hands an operator a prioritized manual-test plan.
15. **Postflight (C2)** — `python -m sec_harness.postflight` distills settled results
   (confirmed findings + rejected-with-rationale + a codebase-security-profile) into the
   durable `kb/prior_context.json`, drift-keyed by SHA; the next scan's C1 ingests it.

Deterministic steps run via `uv run python -m sec_harness.<module>` from `helpers/`.

## Per-repo memory & resume

Every scan persists to an in-repo `<target>/.sec-harness/<slug>/` (override the base
with `$SEC_HARNESS_HOME`, or the workspace with `--workspace`): the KB, `findings/`,
`state.json`, a human `MEMORY.md` index, dated `learnings/`, and reports. The sidecar
is self-ignoring (seeded `.sec-harness/.gitignore`). It survives across runs, so an
interrupted campaign resumes at the next phase.

```bash
python -m sec_harness.cli scan   --target <repo> --config rules/semgrep/<lang>   # defaults workspace to memory
python -m sec_harness.cli memory --target <repo>                                  # status / resumable / next phase
python -m sec_harness.cli memory --target <repo> --learn "..." --tag crypto        # append a learning
```

## Evaluation (`helpers/bench/`, dev-only)

Measures + locks detection quality — not part of a scan:

- **Layer A** detection benchmark: labelled corpus (positives/negatives) → scan via a
  swappable adapter → deterministic-first + LLM-fallback judge → precision/recall by
  source & class + FP-rate.
- **Layer B** regression corpus: a `locked` finding that stops being detected fails the run.
- **Layer C** contract/wiring tests (`tests/test_contracts.py`, `test_wiring.py`):
  prompt↔schema drift + backend reachability, deterministic.

```bash
python -m bench.run --corpus bench/corpus_seed --run-dir /tmp/bench --workspaces <dir>
```

## Feature highlights

- **Adversarial-review all things** — every analysis/context phase (recon, architecture,
  threat-model, C1) ends with a phase adversary gate (deterministic ref-check → independent
  opus challenge) so no phase trusts another's output un-challenged; findings keep the FP
  ladder (critic + adversarial-validate).
- **Red-team static→runtime bridge** — a dedicated phase turns confirmed findings into a
  prioritized MANUAL runtime test plan (`redteam-plan.md`): discriminates static-settled vs
  needs-runtime, emits `$SHELL_VARS` payloads + expected signal + telemetry, high-confidence
  only. Bridges static analysis to what a human tests live; the harness still never executes.
- **Reference-tool hardening** (from Cloudflare-Glasswing `audit` + Anthropic's dynamic
  `defending-code-reference-harness`): shape-based hunting + discovery-noisy/verify-strict +
  severity-from-preconditions + threat-model kill-filter (A); reachability gate, cheap
  finder→critic→judge adjudicator, schema-per-stage validation + in-session repair, fail-open
  parsing, salvage, subsystem partitioning (C); variant-hunt loop, git-history mining, bug-chain
  analysis, logic-chain findings, codify-confirmed-as-semgrep-rule, host-side novelty (B). Durable
  principles + the optional sandboxed runtime mode recorded in the Go-migration doc.
- **Context ingestion + control verification** — reads the repo's own docs/specs/runbooks
  (+ prior scans) into a scan-driving hunt list; C1 verifies claimed controls vs code now and
  writes MISSING/BYPASSABLE ones as candidate findings, adversary-checked. Docs are untrusted
  (leads, never a safe-list). Postflight persists what sticks (`prior_context.json`, drift-keyed).
- ASVS 5.0 + CodeGuard rule-matcher + auto-attached compliance citations on findings.
- Two-tier attack-class catalog: universal + target-conditional `hunting/` domains
  (web-protocol/auth, client-side, AI-agent, business-logic, memory-native) + a 12-heuristic
  methodology and an anti-patterns checklist.
- Redactor + `verify_no_secrets` helpers for masking secrets before they reach a prompt, and an
  untrusted-content envelope (`wrap_untrusted`: nonce + marker-neutralization + attribution
  banner). **Note:** these are helpers the agent prompts instruct agents to use — enforcement is
  prompt-level, not a code-path gate; wire them into your driver if you need a hard guarantee.
- Fix disposition (FULL/MITIGATION/WORKAROUND, cross-field-honest) + a fail-closed gate
  orchestrator + machine-checked crypto policy.

## Develop

```bash
cd helpers && uv run pytest -q          # 242 tests
uv run ruff check sec_harness/ bench/ tests/
```

Design + roadmap: `../../docs/superpowers/specs|plans/2026-07-30-sec-harness-enhancements-*.md`
and `../../docs/sec-harness-go-migration-context.md` (native-Go port, incl. the deferred
tree-sitter call-graph indexer).
