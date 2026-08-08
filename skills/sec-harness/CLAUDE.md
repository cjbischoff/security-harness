# CLAUDE.md — sec-harness operating manual

This file provides guidance to Claude Code (claude.ai/code) when working **inside
`skills/sec-harness/`**. It is the driver for two jobs: (1) running this security-audit skill
against real codebases, and (2) maintaining the skill **without breaking the parallel Go conversion**.

Repo-wide context lives in the root `CLAUDE.md`. This file governs the skill.

---

## 0. Mission — what a good run produces

Run this harness on a target codebase to find **actually-exploitable** vulnerabilities and hand a
security engineer artifacts they can act on. Three standing goals, in priority order:

1. **Signal over noise.** A finding a human acts on must be real. Confirmation requires a
   **mechanical tool receipt** — LLM reasoning alone never confirms. False positives are a defect,
   not an inconvenience.
2. **Exploitability, not pattern-matching.** A syntactic match is a *candidate*, not a finding. The
   bar is a traced source→sink with attacker control and reachability, or an explicit
   `needs-runtime` disposition telling a human exactly what to test on a live system.
3. **Artifacts an engineer can use.** Every run leaves a workspace of durable artifacts: a threat
   model, per-finding JSON with evidence + reachability, a SARIF file, a Markdown report, and a
   `redteam-plan.md` manual test plan. These let a human understand the codebase and test further
   by hand.

Recall matters too: coverage is pursued until a phase can defend it to its adversary; gaps are
**logged, never silently dropped**. Uncertain findings stay `raw`/`candidate` for the ladder to
judge — they are not deleted on a hunch.

---

## 1. Git — protecting the parallel Go conversion (READ FIRST)

A second terminal is porting the skill's Python/helper logic into the Go binary under `go/`. The two
workstreams share this repo. **Boundary is absolute:**

- **You touch only `skills/`.** The Go terminal touches only `go/`. Never edit, stage, or commit
  anything under `go/`. Assume `go/` may have uncommitted work in the working tree at any moment.
- **Never `git add -A`, `git add .`, or `git commit -a`.** Those sweep the other terminal's
  in-progress `go/` edits into your commit. **Always stage explicit skill paths:**
  ```bash
  git add skills/sec-harness/<specific-paths>
  git status          # confirm ONLY skills/ paths are staged; if go/ appears, unstage it
  ```
- **Work on a skill branch, never commit to `main`.** Current branch for this work:
  `skill-audit-driver-YYYYMMDD`. Merge to `main` via PR only after the user approves.
- **Fetch before push:** `git fetch origin && git log origin/<branch>..HEAD` to catch divergence.

### The one coupling point — the JSON contract

The Go port mirrors the Python data contract **byte-for-byte**. `go/bench/gen_golden.py`
instantiates fixed `Finding`/`CampaignState` values against `sec_harness.models` and writes
`json.dumps(obj.to_dict(), indent=2)` (no trailing newline) into `go/internal/model/testdata/`;
Go's `TestParity` asserts byte-equality. **Python is the source of truth; Go conforms to it.**

Two files are the frozen contract — changing them breaks the Go build in the other terminal:

- `helpers/sec_harness/models.py` — `Finding`/`CampaignState` fields, enum `.value` strings
  (note `needs-deployment-testing` is hyphenated), and `to_dict`/`from_dict` behavior.
- `helpers/sec_harness/evidence.py` — the `_MECHANICAL` tool-receipt whitelist that gates
  `confirmed`/`fixed` (see §4). Drift here is a **silent gate weakening**, not just a serialization
  bug.

If you must change either: (a) tell the user so the Go terminal is warned, (b) regenerate goldens
with `python3 go/bench/gen_golden.py` — **but that writes under `go/`, which you do not own**, so
hand that step to the Go terminal or get explicit sign-off. Prefer to avoid touching these two files
at all while the conversion is in flight.

---

## 2. Environment prerequisites for a full run

`helpers/sec_harness/secrets.py` was **reconstructed 2026-07-31** (TDD; it had been missing, which
broke `redactor` and `prefilter` at import). The secrets backend + secret-masking helper now work and
`uv run pytest` collects cleanly. Note `envelope.py:12`'s `import secrets` is the **stdlib** module,
unrelated to this file.

Before a *full* audit, satisfy these environment prerequisites (a clean checkout lacks them):

- **Semgrep rules submodule** — `rules/semgrep/` must be checked out:
  `git submodule update --init --recursive`. Without it, semgrep has no rules and
  `test_preflight.py::test_report_finds_vendored_rules...` fails.
- **External tool binaries** — `uv run python -m sec_harness.preflight` must show `semgrep`,
  `codeql` (+ per-language query packs), `ast-grep`, `osv-scanner`. Missing backends are skipped and
  logged, but a missing CodeQL pack silently drops that language's dataflow (see §3 hard rules).
- **Bench corpus is local-only** — `bench/corpus_seed/*.json` is gitignored (confirmed vulns in
  private code). Its absence fails `test_bench.py::test_seed_corpus_is_valid` and
  `test_citations.py::test_all_mapped_ids_exist_in_seed`; both are **dev/bench** tests, not part of an
  audit. Seed locally to run the bench (§7).

These three failing tests are **environmental** (missing submodule / gitignored seed data), not code
defects — do not "fix" them by committing the submodule contents or fabricating seed data.

---

## 3. How to run an audit

The **main agent orchestrates**; deterministic steps run via `uv run` from
`skills/sec-harness/helpers/`; agent steps spawn a subagent with the named `agents/*.md` prompt
(tokens like `{{TARGET}}`/`{{WORKSPACE}}`/`{{ATTACK_CLASS}}` substituted). Record each phase with
`record_stage(<WS>, "<phase>")` so passes advance. The full operational playbook — every phase in
detail — is **`SKILL.md`**; read it before driving a run. This section is the map.

Legend: `<T>` = target repo, `<WS>` = workspace, `<sha>` = `git -C <T> rev-parse HEAD`,
`<rules>` = a local semgrep ruleset.

### Phase order (one pass)

```
0  Preflight        python -m sec_harness.preflight        # verify semgrep/codeql/ast-grep + CodeQL packs
1  Begin pass       sec_harness.state.begin_pass(WS, sha)  # pins SHA, increments pass counter
C1 Context-ingest   agents/context-ingest.md (sonnet) → context-adversary.md (opus)   # repo docs as UNTRUSTED
T1 Tier-1 substrate  python -m sec_harness.graph build --target <T> --workspace <WS> --sha <sha>
                     # LLM-free: structural_index + regex call-edge heuristic + osv/secrets/crypto facts
                     # → kb/graph.json v1 (consumed by recon, architecture, threat-model)
2  Recon            agents/recon.md (sonnet)     → kb/scan-profile.json     ┐
3  Architecture     agents/architecture.md (sonnet) → kb/architecture.md    ├ each → PHASE GATE
4  Threat model     agents/threat-model.md (sonnet) → kb/THREAT_MODEL.md    ┘   (phase-adversary.md, opus)
0.5 Tune (optional) agents/tune-config.md — ratcheted rule/exclusion loop, ≤3 rounds
5  Prefilter        sec_harness.prefilter.run_prefilter(ws, target, profile) # semgrep+codeql+osv+secrets
6  Investigate      agents/investigate.md (sonnet, PARALLEL per attack-class) → raw / rejected
                    # loop-until-dry: waves until K no-new (saturated) or cap (capped) →
                    #   kb/discovery-ledger.json (discovery_ledger); on pass N>1 prior rejects
                    #   injected as envelope-wrapped negative examples (fp_feedback.{{FP_FEEDBACK}})
   Gate             python -m sec_harness.findings_gate --workspace <WS>
7  Dedupe           python -m sec_harness.dedupe --workspace <WS>
                    # stamps refactor-resistant fingerprint (rule_id|cls|enclosing-symbol via graph)
8  Critic           agents/critic.md (sonnet, PARALLEL) — production-viability filter
   Judge            agents/judge.md (cheap, tool-free) — severity-inflation adjudicator
9  Validate         agents/validate.md (opus, DIFFERENT family) — tries to REFUTE → confirmed / rejected
   Trace            agents/trace.md (opus) — reachability verdict (static-settled vs needs-runtime)
10 Calibrate        python -m sec_harness.calibrate --workspace <WS>   # risk_score 1–10
11 Patch            agents/patch.md (opus, PARALLEL) → patch_diff (throwaway copy only)
   Validate-fix     agents/validate-fix.md (opus; personas: security-architect + penetration-tester)
12 Verify           python -m sec_harness.verify --workspace <WS> --target <T> --config <rules>
13 Gate             python -m sec_harness.findings_gate --workspace <WS>
13.5 Red Team       agents/redteam.md (sonnet) → agents/redteam-adversary.md (opus)
                    python -m sec_harness.redteam --workspace <WS> [--min-risk N]  → redteam-plan.md
14 Report           python -m sec_harness.report --workspace <WS>   → report.sarif + report.md
C2 Postflight       python -m sec_harness.postflight --workspace <WS> --sha <sha>  # durable prior_context
```

### Quick deterministic scan (no agents)

```bash
cd skills/sec-harness/helpers
uv run python -m sec_harness.cli scan \
  --target <T> --workspace <WS> --config rules/smoke.yaml \
  --sha "$(git -C <T> rev-parse HEAD)"
```
Emits `findings/F-*.json`, `report.sarif`, `report.md`, `state.json`. This is the fast smoke path;
the agentic pipeline above is a real audit.

### Hard operating rules during a run

- **A scan is clean only if every PLANNED backend ran.** STOP and surface a setup error if
  `run_prefilter` returns empty `backends_run`, or any planned backend appears in `failed` /
  `skipped_reasons` (e.g. `codeql: pack-missing` = zero dataflow for that language). A partial scan
  (semgrep ran, codeql failed) is a **coverage hole, not "no findings"** — never report it as clean.
- **CodeQL binary present ≠ query packs installed.** Preflight lists installed packs; a missing pack
  silently drops that language's dataflow. Run `codeql pack download codeql/<lang>-queries` if absent.
- **Do not orphan candidates.** The classifier produces classes beyond `agents_to_spawn`
  (`security-other`/`unknown` can hold command-exec/weak-crypto). Call
  `unrouted_candidate_classes(ws, agents_to_spawn)`; if non-empty, log counts and spawn a
  general-triage investigate agent.
- **Fan-out under provider load:** dispatch parallel agents in waves of ~3–4 on a flaky API; a
  transient 429/529 can wipe a one-message batch. Completed candidates carry a terminal status, so
  re-dispatch is safe (skip classes whose candidates are all non-`candidate`).
- **Phase completion:** a phase is done only when ALL its outputs exist AND `record_stage` ran —
  never infer completion from one file's presence.
- **Multi-pass (pass N>1):** scope to changed code with `diffscope.changed_files(<prior_sha>,
  "HEAD")`; `carry_forward(...)` re-checks settled findings on changed files (→ `stale`) and keeps
  those on unchanged files. Full re-scan is the safe default; incremental is the token optimization.
- **The Tier-1 substrate is always built** (never behind a flag); `no_path` receipts are only valid
  after Tier-2 taint merge at prefilter.

---

## 4. Signal-over-noise architecture (why findings are trustworthy)

This is the core value of the harness. Four layered mechanisms — do not weaken any of them:

**a) Tool-receipt confirmation gate.** A finding reaches `confirmed`/`fixed` only with ≥1
`evidence_sources` entry that `evidence.is_tool_receipt()` accepts. Enforced in
`findings_gate.py:50-58`. The whitelist (`evidence.py` `_MECHANICAL`): `semgrep`, `codeql`,
`ast-grep`, `tree-sitter`, `ripgrep`, `structural-index`, `secrets`, `sca`. LLM assertions are
`llm-claimed:*` and **corroborate but never confirm**. Colon form: `semgrep:<rule>`,
`codeql:dataflow`, `ast-grep:sink`, `structural-index:callers`.

**b) Gate ladder in `investigate.md`** (each rung needs a recorded receipt): Gate −1
sanity/hallucination (cited code absent/different → DISCARD), Gate 0 design intent, Gate 1
reachability, Gate 2a attacker control, Gate 2b sanitizer scope (never trust a function *named*
`sanitize`/`validate`), Gate 3 new capability. Investigate is **recall-biased** (keep unsure as
`raw`); the later stages are precision-biased.

**c) Adversarial validation with model-family diversity.** Every load-bearing artifact is
pressure-checked by an independent adversary on a **different, stronger model family** than the
producer (opus vs the sonnet producer). This is mandatory, not optional — parallelism does not relax
it. If only one family is available, degrade to a fresh-context validator and **log it — never let
the finder be the sole confirmer.**
  - Findings: `critic` → `judge` → `validate` (validate tries to *refute*; survival = confirmation).
  - Analysis/context phases: `phase-adversary.md` (recon/architecture/threat-model), plus a
    deterministic `phase_gate.run_phase_checks` that rejects claims whose cited `file:line` doesn't
    resolve — with no agent call at all.
  - Context: `context-adversary.md`. Red-team plan: `redteam-adversary.md`.
  - **Safety contract, everywhere:** adversarial *reasoning* alone demotes/downgrades but never
    deletes a tool-receipt-backed finding — only a competing tool receipt can.

**d) Derived severity + FP discipline.** `SEVERITY_PRECONDITION` forces preconditions enumerated
*before* a severity band (kills "SQLi ∴ critical" anchoring); the harness computes CVSS, not the LLM.
`validate.md` requires a `file:line` citation to reject as false-positive, and never launders a
`verify-error` into a clean verdict. `needs-deployment-testing` is a real terminal state for
real-but-unprovable-from-source findings — never folded into `confirmed` or `rejected`.

**The static→runtime bridge (`redteam-plan.md`)** is where exploitability judgment reaches the
human: `runtime_disposition` splits `static-settled` from `needs-runtime`; only findings at/above the
confidence bar (`risk_score >= min-risk`, default 7) become actionable manual test directives (with
`$SHELL_VAR` payloads, never literal secrets). Weaker candidates land in "runtime-validation gaps".
The harness **never executes the target** — it emits a plan a person runs.

---

## 5. Workspace artifacts (what a security engineer gets)

Default workspace: `<target>/.sec-harness/<repo-slug>/` — an in-repo, self-ignoring sidecar next to
the reviewed code (override base `$SEC_HARNESS_HOME`; override entirely with `--workspace`). The
read-only invariant is about the reviewed **source**, not this folder.

```
kb/scan-profile.json     recon output: languages, frameworks, attack_surface, sast_plan, subsystems
kb/architecture.md       component/data-flow/trust-boundary map + kb/entities/*.md
kb/THREAT_MODEL.md       trust boundaries, attacker profiles, PRIORITIZED HUNT LIST
kb/context.json          repo's own docs distilled (trust-tagged untrusted-doc / prior-scan)
kb/gates/<phase>.json    adversary verdict audit trail per gated phase
kb/discovery-ledger.json investigate saturation state (waves, consecutive_no_new, terminal_reason)
kb/coverage-ledger.json  surface-completeness ledger; `complete` machine-rejected while gaps remain
findings/<ID>.json       every finding, all statuses — evidence_sources, reachability, cvss, patch_diff
report.sarif             SARIF 2.1.0 (confirmed/fixed)
report.md                human report (finding-template.md structure; links redteam-plan.md)
redteam-plan.md          manual runtime test plan — the engineer's follow-up
state.json               campaign state (pass number, pinned SHA, stages)
MEMORY.md, learnings/     durable per-repo memory across runs
```

Resume an interrupted campaign: `python -m sec_harness.cli memory --target <T>` reports
`{finished, resumable, next_phase, stages_done}`.

---

## 6. Reference knowledge — consult, don't guess

Under `references/`. Agents load these by target type; know when each applies:

- **`prompt-constants.md`** — six verbatim blocks (`ANTI_MANIPULATION`, `EXCLUSION_RULES`,
  `SEVERITY_GUIDANCE`, `SEVERITY_PRECONDITION`, `SHAPE_HUNTING`, `TOOL_TRUST`) injected into **every**
  agent so scope/severity/anti-manipulation rules never drift. All agents wrap untrusted repo text in
  the trust envelope and import these.
- **`attack-classes.md`** — canonical attack-class keys + ripgrep indicators; recon uses it to fill
  `attack_surface`/`agents_to_spawn` (evidence-based only; empty beats guessed).
- **`hunting/`** — deep exploit-reasoning companions, loaded conditionally: `methodology.md` +
  `anti-patterns.md` (always — the operational core of signal-over-noise, with per-class "FP trap"
  callouts), `business-logic.md`, `web-protocol-auth.md` (proxies/JWT/OAuth/SAML), `ai-agent.md`
  (LangChain/MCP/RAG), `memory-native.md` (**only** when C/C++/Rust-unsafe/cgo present),
  `client-side.md` (SPA/browser).
- **`codeguard/`** — 7 terse secure-coding checklists per domain (used by patch/triage for correct
  remediation shape).
- **`approved-crypto-algorithms.yaml` / `approved-key-sources.yaml`** — machine-checked by
  `crypto_policy.check` (denies md5/sha1/des/ecb, floors rsa≥3072/pbkdf2≥100000/ecc≥256, denies
  literal/hardcoded key sources). Turns "weak crypto" into a deterministic lookup.
- **`asvs/asvs_5.0.0.json`** (curated 12-item seed), **schemas** (`scan-profile`, `fix-disposition`),
  **`finding-template.md`** (9-section report bound field-by-field to the `Finding` record),
  **`DETECTION_COVERAGE.md`** (honest tool-coverage + limitations — directs agent effort to gaps SAST
  can't see: Liquid/Handlebars templates, single-function OSS-semgrep taint, no CodeQL for PHP).

---

## 7. Developing the skill

From `skills/sec-harness/helpers/`:

```bash
uv run pytest -q                                   # full suite (3 env-only failures — see §2)
uv run pytest tests/test_fingerprint.py -q         # single file
uv run pytest tests/test_x.py::test_name           # single test
uv run ruff check sec_harness/ bench/ tests/       # lint (line-length 100)
uv run ruff format sec_harness/ bench/ tests/
uv run ty check                                    # static types
uv run python -m sec_harness.preflight             # tool availability
```

**Conventions:**
- The core is **stdlib-only by design** — no runtime dependencies in `pyproject.toml` (dev deps:
  pytest, ruff, ty only). Do not add a dependency without a strong justification and user sign-off.
- **TDD for skill code.** The missing-`secrets.py` fix already has failing tests waiting — reconstruct
  to make them pass. `tests/test_contracts.py` + `tests/test_wiring.py` catch prompt↔schema drift and
  silent-backend regressions; keep them green.
- **`helpers/bench/` is dev-only** — a labelled-corpus precision/recall + regression harness, **not**
  part of an audit run. A `locked` positive that stops being detected is a hard failure. Run:
  `python -m bench.run --corpus bench/corpus_seed --run-dir /tmp/bench --workspaces <dir>`. Its
  `BinaryAdapter` is the seam that will regression-test the Go binary against this Python contract.
- **Semgrep rules are a git submodule** (`helpers/rules/semgrep/`). Clone with `--recurse-submodules`.
- When editing an `agents/*.md` prompt, preserve its hard rules verbatim (model-family diversity,
  tool-receipt safety contract, count-invariant verdict tables) — these are load-bearing, not prose.
- CLI-callable modules (`python -m sec_harness.<module>`): `cli`, `preflight`, `postflight`,
  `calibrate`, `dedupe`, `verify`, `report`, `redteam`, `bugchain`, `astgrep`, `structural_index`,
  `citations`, `findings_gate`, `rule_gaps`, `redactor`, `graph`.

---

## 8. Documentation — READMEs track code (enforced)

Each of the three working folders carries a **human-oriented README** that over-explains what
lives there and how it works, with mermaid diagrams and worked flows. They are the entry point
for a person (not just an LLM) trying to understand this codebase — keep them current.

| README | Covers |
|--------|--------|
| [`README.md`](README.md) | the map: invariants, architecture, the pipeline, and a full end-to-end **worked example** (one SQLi finding from candidate → confirmed → fixed → redteam-plan). Points at the three folder READMEs and `SKILL.md`. |
| [`agents/README.md`](agents/README.md) | every LLM prompt: role, model tier (sonnet producer / opus adversary), inputs/outputs, the producer→adversary rule, the investigate gate ladder, and the `classes/` extensions. |
| [`helpers/README.md`](helpers/README.md) | the ~70 Python modules grouped by job, the CLI-callable list, the deterministic pipeline diagram, the two frozen contracts, and the two in-code invariants. |
| [`references/README.md`](references/README.md) | the rule book: the 9 `prompt-constants.md` blocks, `attack-classes.md`, the schemas, the crypto-policy YAMLs, and which module/agent consumes each file. |

**Hard rule — docs track code in the same commit.** When you change anything under `agents/`,
`helpers/`, or `references/`, update that folder's `README.md` in the **same commit**. This is
enforced by a scoped pre-commit hook at `.githooks/pre-commit`:

```bash
# one-time, repo-local install (safe for the Go workstream — the hook no-ops
# on commits that touch nothing under skills/sec-harness/):
git config core.hooksPath skills/sec-harness/.githooks
```

The hook only inspects staged files under `skills/sec-harness/{agents,helpers,references}`; it
never reads, stages, or blocks `go/`. Bypass a genuinely doc-neutral change (e.g. a pure
formatting pass) with `git commit --no-verify`.

> **Caution when self-testing git flows here:** never run `git stash -u` while these READMEs (or
> other new untracked files) are unstaged — `-u` sweeps untracked files into the stash and they
> vanish from the tree until you `stash pop`. Stage or commit first.
