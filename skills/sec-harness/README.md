# sec-harness

A self-contained, **agentic security-audit harness**. Point it at a codebase and it finds
*actually-exploitable* vulnerabilities, then hands a security engineer artifacts they can act
on: a threat model, per-finding evidence, a SARIF file, a Markdown report, and a manual
runtime-test plan.

The core idea in one sentence: **run cheap mechanical tools to find candidates, use LLM
agents to investigate whether each candidate is real, and never let an LLM's opinion alone
confirm a finding — a mechanical tool receipt is always required.**

This README is the map. It explains *how the whole thing fits together* and hands you off to
the three folder READMEs and the operational playbook for detail.

| To understand… | Read |
|----------------|------|
| The full phase-by-phase operating playbook | [`SKILL.md`](SKILL.md) |
| Git protocol, the Go-port contract, environment setup | [`CLAUDE.md`](CLAUDE.md) |
| The LLM prompts that investigate/validate/patch | [`agents/README.md`](agents/README.md) |
| The Python core that runs tools & enforces gates | [`helpers/README.md`](helpers/README.md) |
| The rule book (severity, scope, schemas, crypto policy) | [`references/README.md`](references/README.md) |

---

## The four invariants (what makes findings trustworthy)

These hold everywhere and are enforced in code where possible, prompt otherwise:

1. **Never executes or modifies the reviewed source.** Static analysis only. Patches are
   applied to a *throwaway copy* to verify them — the repo's own files are never run or edited.
2. **Writes only its own sidecar.** All output lives in an in-repo, self-ignoring
   `<target>/.sec-harness/<slug>/` directory (override the base with `$SEC_HARNESS_HOME`, or
   the whole workspace with `--workspace`). A seeded `.sec-harness/.gitignore` keeps output
   out of the reviewed repo's git tree.
3. **Tool-receipt gate.** A finding reaches `confirmed`/`fixed` only with ≥1 mechanical
   receipt (`semgrep` / `codeql` / `ast-grep` / `tree-sitter` / `ripgrep` /
   `structural-index` / `secrets` / `sca`). LLM reasoning is namespaced `llm-claimed:` and can
   corroborate but **never** confirm. Enforced in `helpers/…/findings_gate.py`.
4. **Signal over noise.** Every load-bearing claim made by a Sonnet "producer" is attacked by
   an Opus "adversary" on a different model family; a false-positive ladder + a
   `needs-deployment-testing` verdict for bugs unprovable-from-source keep the report clean.

---

## Architecture — three folders, three jobs

```mermaid
flowchart TB
    subgraph HARNESS["skills/sec-harness/"]
        direction TB
        SKILL["SKILL.md<br/>the orchestration playbook"]
        subgraph REF["references/ — the RULE BOOK"]
            R1["prompt-constants, attack-classes,<br/>schemas, crypto policy, hunting/ guides"]
        end
        subgraph AG["agents/ — the JUDGEMENT"]
            A1["~30 LLM prompts:<br/>producer (sonnet) vs adversary (opus)"]
        end
        subgraph HP["helpers/ — the MACHINE"]
            H1["~70 stdlib-only Python modules:<br/>run SAST, enforce gates, write reports"]
        end
    end
    TARGET[("target codebase<br/>(read-only)")]
    OUT[("<target>/.sec-harness/<slug>/<br/>KB + findings + reports")]

    SKILL -->|drives| AG
    SKILL -->|calls| HP
    AG -->|"reads rules"| REF
    HP -->|"reads schemas/policy"| REF
    HP -->|"reads only"| TARGET
    AG -->|"reads only"| TARGET
    HP -->|"writes"| OUT
    AG -->|"writes"| OUT
```

- **`references/`** is stated once, obeyed everywhere — severity bands, scope rules, JSON
  schemas, the crypto allow/deny lists, and the deep hunting guides. → [details](references/README.md)
- **`agents/`** are the LLM prompts. Producers (Sonnet) find things; adversaries (Opus, a
  different family) try to prove them wrong. → [details](agents/README.md)
- **`helpers/`** is the deterministic Python that runs the tools and *enforces the gates no
  LLM is trusted to enforce.* Stdlib-only. → [details](helpers/README.md)

The main agent (you, driving [`SKILL.md`](SKILL.md)) is the orchestrator: it calls a Python
step, spawns an agent, records the phase, calls the next Python step.

---

## The pipeline

One audit pass, in order. Deterministic (Python) steps are rectangles; agent (LLM) steps are
rounded. `<T>` = target, `<WS>` = workspace.

```mermaid
flowchart TD
    P0["0 · preflight<br/>tools + CodeQL packs present?"] --> P1["1 · begin_pass<br/>pin SHA"]
    P1 --> C1(("C1 · context-ingest → context-adversary<br/>repo docs as UNTRUSTED leads"))
    C1 --> T1["T1 · graph build<br/>Tier-1 substrate (LLM-free)"]
    T1 --> RA(("2-4 · recon → architecture → threat-model<br/>each gated by phase-adversary (opus)"))
    RA --> PRE["5 · prefilter<br/>semgrep+codeql+sca+secrets, never-silent"]
    PRE --> INV(("6 · investigate<br/>parallel per class, loop-until-dry"))
    INV --> DED["7 · dedupe<br/>refactor-resistant fingerprint"]
    DED --> LAD(("8-9 · critic → judge → validate(opus refutes)"))
    LAD --> CAL["10 · calibrate<br/>risk_score 1-10 + citations"]
    CAL --> PAT(("11 · patch(opus) → validate-fix"))
    PAT --> VER["12 · verify<br/>apply patch to COPY, re-scan"]
    VER --> GATE["13 · findings_gate"]
    GATE --> RT(("13.5 · redteam → redteam-adversary"))
    RT --> RTR["redteam.py → redteam-plan.md"]
    RTR --> REP["14 · report<br/>report.sarif + report.md"]
    REP --> C2["C2 · postflight<br/>durable prior_context.json"]
```

The phase legend with exact commands is in [`SKILL.md`](SKILL.md); the hard operating rules
(a partial scan is a coverage hole, not "clean") are in [`CLAUDE.md`](CLAUDE.md) §3.

---

## Worked example — one SQL-injection finding, end to end

To make the flow concrete, here is what happens to a single bug as it moves through the
pipeline. Say the target is a Flask app with this route:

```python
# app/routes.py
@app.route("/user")
def get_user():
    uid = request.args.get("id")               # attacker-controlled
    return db.execute("SELECT * FROM users WHERE id = " + uid)   # string-built SQL
```

| Phase | What runs | What happens to this bug | Artifact touched |
|-------|-----------|--------------------------|------------------|
| **C1 context** | `context-ingest` (sonnet) | Reads the repo's docs; a runbook *claims* "all inputs validated by middleware." That claim is tagged **untrusted** — it becomes a lead to verify, not a safe-list. | `kb/context.json` |
| **T1 substrate** | `graph build` (no LLM) | Builds a call graph: `request.args` is an entry point; `db.execute` is a sink; there's a one-hop edge between them. | `kb/graph.json` |
| **2-4 analysis** | recon → architecture → threat-model | `injection` lands on the prioritized hunt list because recon saw Flask + raw SQL; opus phase-adversary confirms the entrypoint claim resolves to real code. | `kb/scan-profile.json`, `THREAT_MODEL.md` |
| **5 prefilter** | semgrep + codeql (no LLM) | semgrep's SQLi rule fires on line 4 → a **candidate** with a real receipt `semgrep:<rule>`. | `findings/C-0001.json` (candidate) |
| **6 investigate** | `investigate.md` (sonnet, `injection`) | Walks the gate ladder: cited code exists (Gate −1 ✓), reachable from `request.args` (Gate 1 ✓, `codeql:dataflow` receipt), `uid` is attacker-controlled (Gate 2a ✓), **reads the claimed middleware — it only trims whitespace, doesn't parameterize** (Gate 2b: sanitizer does *not* apply ✓), yields DB read/write (Gate 3 ✓). Promoted to **`raw`**. | status → `raw` |
| **7 dedupe** | `dedupe` (no LLM) | Stamps fingerprint `sha256(sqli\|injection\|get_user)` so a later refactor that shifts the line still maps to the same finding. | `fingerprint` field |
| **8 critic** | `critic.md` (sonnet) | It's on a live route, not debug/test code → stays `raw`. | history: `critic:viable` |
| **9 validate** | `validate.md` (**opus**) | *Assumes it's wrong* and re-traces independently, trying to refute. Cannot find a sanitizer on any path → **survives** → **`confirmed`**. (To reject it would have needed a `file:line` cite of a real defeating control.) | status → `confirmed` |
| **10 calibrate** | `calibrate` (no LLM) | Preconditions enumerated first (unauthenticated, no WAF assumed) → CVSS computed by formula → `risk_score: 9`. ASVS/CodeGuard citations auto-attached. | `risk_score`, `asvs_ids` |
| **11 patch** | `patch.md` (opus) | Proposes a parameterized-query diff into `patch_diff` — against a *copy*, never the real file. | `patch_diff` |
| **12 verify** | `verify` (no LLM) | Applies the diff to a temp copy, re-runs semgrep → the rule no longer fires → **`fixed` / verified-static**. | status → `fixed` |
| **13.5 redteam** | `redteam` → `redteam-adversary` | Marks it `static-settled` (source proves it) but still writes a `runtime_test` with a `$PAYLOAD` shell var so an operator can confirm live; opus adversary keeps it (payload ties to the real sink). | `redteam-plan.md` |
| **14 report** | `report` (no LLM) | Renders the finding into `report.md` (9-section template) and `report.sarif`. | `report.md`, `report.sarif` |
| **C2 postflight** | `postflight` | Records "confirmed SQLi in get_user, fixed at <sha>" into durable memory so the next scan doesn't re-litigate it. | `kb/prior_context.json` |

The point of the table: **no single step is trusted.** A tool found it, a sonnet agent
investigated it, an opus agent tried to kill it, a deterministic module scored it, and a
second deterministic module proved the fix — each leaving a receipt on disk.

---

## How to run it

### Quick deterministic smoke scan (no agents)
Fastest way to see output. From `helpers/`:

```bash
cd helpers
uv run python -m sec_harness.cli scan \
  --target <path-to-code> \
  --config rules/smoke.yaml \
  --sha "$(git -C <path-to-code> rev-parse HEAD)"
# workspace defaults to <target>/.sec-harness/<slug>/
```

This runs semgrep → normalize → SARIF/Markdown only. It is the smoke path, **not** a real
audit (no agents, no gate ladder).

### Full agentic audit
Driven by the main agent following [`SKILL.md`](SKILL.md). The short version:

```bash
cd helpers
uv run python -m sec_harness.preflight        # 0 — verify semgrep/codeql/ast-grep + CodeQL packs
# 1  begin_pass(WS, sha)
# C1 spawn agents/context-ingest.md → context-adversary.md
uv run python -m sec_harness.graph build --target <T> --workspace <WS> --sha <sha>   # T1
# 2-4 spawn recon → architecture → threat-model (+ phase-adversary each)
# 5  from sec_harness.prefilter import run_prefilter; run_prefilter(ws, target, profile)
# 6  spawn agents/investigate.md in parallel per attack class
uv run python -m sec_harness.dedupe        --workspace <WS>    # 7
# 8-9 spawn critic → judge → validate
uv run python -m sec_harness.calibrate     --workspace <WS>    # 10
# 11 spawn patch → validate-fix
uv run python -m sec_harness.verify        --workspace <WS> --target <T> --config <rules>   # 12
uv run python -m sec_harness.findings_gate --workspace <WS>    # 13
# 13.5 spawn redteam → redteam-adversary
uv run python -m sec_harness.redteam       --workspace <WS>
uv run python -m sec_harness.report        --workspace <WS>    # 14
uv run python -m sec_harness.postflight    --workspace <WS> --sha <sha>   # C2
```

> **A scan is clean only if every planned backend actually ran.** If `preflight` shows a
> missing CodeQL pack, that language has *zero dataflow coverage* — a partial scan is a
> coverage hole, not "no findings." See [`CLAUDE.md`](CLAUDE.md) §3.

---

## What you get — the output workspace

Everything lands in `<target>/.sec-harness/<slug>/` (self-ignoring):

```
kb/scan-profile.json      recon output: languages, frameworks, attack_surface, sast_plan
kb/architecture.md        components, data flows, trust boundaries (+ kb/entities/*.md)
kb/THREAT_MODEL.md        attacker profiles + the prioritized hunt list
kb/context.json           the repo's own docs distilled, trust-tagged
kb/graph.json             the Tier-1/Tier-2 code graph (reachability substrate)
kb/gates/<phase>.json     adversary verdict audit trail per gated phase
kb/coverage-ledger.json   surface-completeness (blocks "complete" while gaps remain)
kb/discovery-ledger.json  investigate saturation state
findings/<ID>.json        every finding, all statuses — evidence, reachability, cvss, patch
report.sarif              SARIF 2.1.0 (confirmed/fixed)
report.md                 the human report (finding-template structure)
redteam-plan.md           the manual runtime test plan — the engineer's follow-up
state.json                campaign state (pass number, pinned SHA, stages)
MEMORY.md, learnings/     durable per-repo memory across runs
```

**Resume** an interrupted run: `python -m sec_harness.cli memory --target <T>` reports
`{finished, resumable, next_phase, stages_done}`.

---

## Develop

From `helpers/` (stdlib-only core; dev deps pytest/ruff/ty):

```bash
uv run pytest -q          # ~470 tests (3 env-only failures — see CLAUDE.md §2)
uv run ruff check sec_harness/ bench/ tests/
uv run ty check
```

Two coupling points to respect before editing:

- **The Go port.** `helpers/sec_harness/models.py` and `evidence.py` are a byte-for-byte
  frozen contract with a parallel Go rewrite under `go/`. Changing a field or the mechanical
  whitelist breaks the Go build — coordinate first. Never touch `go/`. See [`CLAUDE.md`](CLAUDE.md) §1.
- **Docs track code.** When you change anything in `agents/`, `helpers/`, or `references/`,
  update that folder's README in the **same commit**. A pre-commit hook enforces this — see
  [`CLAUDE.md`](CLAUDE.md) §8.
