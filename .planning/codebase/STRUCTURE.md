# Codebase Structure

**Analysis Date:** 2026-07-30

**Scope:** `skills/sec-harness/` only. `reference_tools/`, `test_repos/`, `docs/`, and
`skills/sec-harness/helpers/rules/semgrep/` (git submodule) are out of scope.

## Directory Layout

```
skills/sec-harness/
├── SKILL.md                    # Orchestration contract — the main agent's playbook
├── agents/                     # LLM phase prompts (markdown templates, {{TOKEN}} slots)
│   ├── recon.md architecture.md threat-model.md      # KB build (sonnet, phase-gated)
│   ├── context-ingest.md context-adversary.md        # C1 context (sonnet + opus)
│   ├── investigate.md critic.md judge.md validate.md # FP ladder
│   ├── patch.md validate-fix.md                      # remediation
│   ├── redteam.md redteam-adversary.md trace.md      # static→runtime bridge
│   ├── phase-adversary.md                            # reusable phase gate adversary
│   ├── bugchain.md variant-hunt.md factcheck.md tune-config.md postflight.md
│   └── classes/                # per-attack-class investigate sub-prompts
│       └── authz.md config.md crypto.md injection.md resource.md
├── references/                 # Static knowledge loaded by agent prompts
│   ├── prompt-constants.md     # trust envelope + shared prompt constants
│   ├── attack-classes.md finding-template.md anti-patterns.md
│   ├── DETECTION_COVERAGE.md
│   ├── scan-profile.schema.json fix-disposition.schema.json
│   ├── approved-crypto-algorithms.yaml approved-key-sources.yaml
│   ├── asvs/ codeguard/        # rule-matcher corpora (F1)
│   └── hunting/                # methodology playbooks by domain
│       └── methodology.md web-protocol-auth.md ai-agent.md
│           business-logic.md client-side.md memory-native.md anti-patterns.md
└── helpers/                    # Deterministic Python core + tooling
    ├── pyproject.toml uv.lock  # uv-managed project
    ├── sec_harness/            # ~57 single-concern modules (see below)
    ├── bench/                  # dev-only detection-quality eval harness
    ├── tests/                  # pytest suite (one test_*.py per module + contracts/wiring)
    ├── fixtures/               # scan fixtures
    └── rules/                  # semgrep rulesets (smoke.yaml + semgrep/ submodule — OUT OF SCOPE)
```

## Directory Purposes

**`agents/`** — one markdown prompt per LLM phase. Not executable; the main agent spawns
each as a subagent with `{{TARGET}}`/`{{WORKSPACE}}`/`{{ATTACK_CLASS}}`/`{{PHASE}}`/`{{ROUND}}`
substituted. `agents/classes/` holds per-attack-class investigate specializations.

**`references/`** — static, version-controlled knowledge the prompts pull in: attack-class
taxonomy, finding template, JSON schemas, approved-crypto allowlists, and ASVS/CodeGuard
corpora for `rule_matcher.py`. `references/hunting/` is domain methodology (web/auth, AI-agent,
business-logic, client-side, memory-native).

**`helpers/sec_harness/`** — the deterministic core. Every module is one concern; ~15 expose a
`python -m` CLI (pipeline steps), the rest are libraries imported by CLIs/agents.

**`helpers/bench/`** — dev-only eval harness (NOT part of a scan): labelled corpus → swappable
adapter → judge → precision/recall + regression gate. Files: `adapter.py corpus.py judge.py
run.py tally.py` + `corpus_seed/`. See `helpers/bench/README.md`.

**`helpers/tests/`** — pytest, one `test_<module>.py` per core module, plus `test_contracts.py`
(prompt↔schema drift) and `test_wiring.py` (silent-backend regressions). Fixtures in
`fixtures/` and `fixtures_struct/`; `conftest.py` for shared config.

## Key File Locations

**Entry points:**
- `helpers/sec_harness/cli.py`: `python -m sec_harness.cli scan|memory`.
- Per-phase CLIs: `preflight, dedupe, calibrate, verify, findings_gate, redteam, report,
  postflight, structural_index, bugchain, astgrep, citations, redactor, rule_gaps`
  (each `python -m sec_harness.<name>`).
- `SKILL.md`: orchestration contract binding it all.

**Core contract:**
- `helpers/sec_harness/models.py`: `Finding`, `CampaignState`, `FindingStatus`, `Severity`.
- `helpers/sec_harness/workspace.py`: `Workspace` layout + `read_findings`/`write_findings`.

**Configuration:**
- `helpers/pyproject.toml` + `helpers/uv.lock`: uv project.
- `helpers/rules/smoke.yaml`: default semgrep ruleset.
- `references/*.schema.json`, `references/*.yaml`: schemas + crypto allowlists.

**Core logic (by concern):**
- SAST/prefilter: `prefilter.py sast.py semgrep`(via `sast.py`)`codeql.py astgrep.py sca.py secrets.py normalize.py`
- FP ladder/scoring: `dedupe.py fingerprint.py calibrate.py cvss.py scoring.py evidence.py judge`(prompt)
- Gates: `findings_gate.py phase_gate.py gates.py fix_disposition.py crypto_policy.py`
- Remediation/verify: `verify.py reachability.py`
- Red team: `redteam.py`
- Context/campaign: `context.py campaign.py state.py diffscope.py postflight.py repo_memory.py`
- Recall loops: `variant.py bugchain.py githist.py rule_gaps.py novelty.py factcheck.py`
- Output: `report.py sarif.py redactor.py citations.py`
- Recon/profile: `profile.py recon`(prompt)`structural_index.py partition.py clsmap.py coverage_guide.py detection_coverage.py`
- Rule/standards matching: `rule_matcher.py asvs.py codeguard.py`
- Support: `kb.py envelope.py parse.py stage_validate.py exclusions.py tuning.py preflight.py`

**Testing:** `helpers/tests/test_<module>.py`; contract/wiring in `test_contracts.py`,
`test_wiring.py`; e2e in `test_cli_e2e.py`.

## Naming Conventions

**Modules:** lowercase, one concern per file, name = concern (`calibrate.py`, `redteam.py`).
Phase-step modules carry a `main()` + `if __name__ == "__main__"` block.

**Finding ids:**
- Deterministic prefilter candidates: `C-####`.
- Deterministic scan (cli): `F-####`.
- Investigate (per-class, LLM): **class-prefixed** — `SQLI-0001`, `CTL-####` (context controls),
  `A-####`. Class prefix prevents id contention across parallel per-class agents.

**Agent prompts:** `agents/<phase>.md`; adversaries suffixed `-adversary.md`; class prompts
under `agents/classes/<class>.md`.

**Tests:** `helpers/tests/test_<module>.py`, mirroring `sec_harness/<module>.py`.

**KB/gate artifacts:** `kb/gates/<phase>.json`, `kb/tuning/round_k/`, `kb/entities/*.md`.

## Where to Add New Code

**New pipeline phase (deterministic):** add `helpers/sec_harness/<phase>.py` with a `main()`
+ `python -m` block; add `helpers/tests/test_<phase>.py`; wire the step into `SKILL.md` and,
if it produces findings, into `findings_gate`/report. Follow the existing small-module pattern.

**New LLM phase:** add `agents/<phase>.md` using `{{TOKEN}}` slots; import
`references/prompt-constants.md` (trust envelope); if adversary-gated, pair with
`agents/<phase>-adversary.md` and record via `phase_gate.build_gate_record`/`write_gate_record`.

**New attack class:** add `agents/classes/<class>.md`, register in `clsmap.py` (rule-id → class
router), extend `references/attack-classes.md`, and ensure recon's `agents_to_spawn` can emit it.

**New quality gate:** add a callable to `gates.GATE_ROUTING` (one row); mark required in
`gates.REQUIRED_GATES` if non-waivable.

**Shared helpers:** small utilities live in their own module (`parse.py`, `envelope.py`,
`kb.py`) — reuse before adding; no util grab-bag.

## Special Directories

**`helpers/rules/semgrep/`** — git submodule (vendored rulesets). Out of scope; do not edit.
**`helpers/bench/corpus_seed/`** — seeded labelled corpus for the eval harness. Committed.
**`.ruff_cache/`, `.pytest_cache/`** — generated tool caches. Not committed (gitignored).
**`~/.sec-harness/<repo-slug>/`** — runtime per-repo memory/workspace (outside the repo; created
by `repo_memory.py`, keyed by git origin or path + hash; overridable via `$SEC_HARNESS_HOME`).

---

*Structure analysis: 2026-07-30*
