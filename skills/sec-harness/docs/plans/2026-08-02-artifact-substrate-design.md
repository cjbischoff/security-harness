# Design: Analysis Artifacts + Shared Evidence Substrate

Date: 2026-08-02
Status: Approved design (pre-implementation)
Scope: `skills/sec-harness/` only. Does not touch the `go/` workstream or the frozen
JSON contract (`helpers/sec_harness/models.py`, `helpers/sec_harness/evidence.py`).

## 1. Motivation

Two problems, one solution.

1. Missing human deliverables. `xvnpw/ai-security-analyzer` produces polished security
   artifacts we do not: a C4 security-design document, a full threat model with
   Application / Deployment / Build sub-models, an attack-surface analysis, and an
   attack tree with quantified node attributes. These are valuable to developers and
   security engineers. Our `THREAT_MODEL.md` is a terse internal hunt list, not a
   deliverable; we emit no C4 doc and no attack tree.

2. Wasted re-analysis. The same structural question — *can untrusted input reach this
   sink, and does an attacker control it?* — is re-derived by LLM at multiple phases:
   architecture (data-flow tracing), threat-model (prioritize by reachability),
   investigate (Gate 1 reachability + Gate 2a attacker-control), trace (reachability
   verdict), and validate (re-read to refute). That is one deterministic fact answered
   ~5× as fresh LLM passes over raw code.

The reference tool solves (1) but has no verification at all — every claim is unbacked
LLM assertion. We reject that. This design adopts its artifacts while subjecting every
claim to our existing discipline, and in doing so also solves (2): the structural facts
those artifacts need are computed once into a shared substrate and reused everywhere,
including to *disprove* findings.

## 2. Principles (invariants applied to every phase)

1. Every artifact's claims are adversarially reviewed. Not just findings — the C4 doc,
   threat model, attack surface, attack tree, and mitigations each run the two-gate
   discipline already used on recon/architecture/threat-model:
   - `phase_gate` (deterministic): every cited `file:line` must resolve or the claim is
     dropped as a hallucination.
   - `phase-adversary` (LLM, opus, different family from the producer): pressure-tests
     the reasoning.
   Safety contract everywhere: a competing *receipt* can refute a claim; adversarial
   *reasoning* alone only demotes/downgrades, never deletes a receipt-backed item.

2. Previous artifacts drive later phases. Each phase reads the *validated* artifacts of
   prior phases, not just raw code. Findings carry anchors (file:line + substrate node
   id) so downstream phases locate them instead of re-scanning.

3. Deterministic + defined-tool + LLM in every phase, routed to the goal. Each phase
   uses the cheapest analysis that answers its question: deterministic tools for
   structural/factual claims (which yield receipts), LLM only for interpretation and
   adversarial judgment the tools are blind to (business logic, authz, threat framing).

4. Compute-once, cite-many. Reachability / attacker-control / structure are computed
   once into `kb/graph.json` and queried by every phase — including as negative evidence
   to disprove a finding (`structural-index:no-path` is already in the `_MECHANICAL`
   receipt whitelist).

## 3. The shared evidence substrate (`kb/graph.json`)

Not greenfield. Assembled from existing modules: `structural_index.py`,
`reachability.py`, `astgrep.py`, `codeql.py`, `sca.py`, `secrets.py`, `crypto_policy.py`.
No external MCP (code-review-graph MCP is unavailable and would break the stdlib-only,
Go-portable mandate anyway).

Two-tier build:

- Tier-1 (cheap, no LLM, runs in the Understand stage before the analysis agents):
  `structural_index` + `ast-grep` produce nodes (entrypoints, components, sinks) and
  edges (calls, imports); `osv-scanner` + `secrets` + `crypto_policy` attach dependency,
  secret, and crypto facts. Grounds the early artifact drafts so they are not guesses.
- Tier-2 (heavy, deterministic, at prefilter): `semgrep` + `codeql` taint add dataflow
  reachability edges. Refines the substrate; enables receipt-backed reachability.

Contract: every node/edge/fact is a deterministic receipt or is absent. Artifacts are
*projections* of this substrate plus LLM interpretation. Findings *anchor* to node ids.
Verification phases *query* it rather than re-deriving.

Query surface used across phases:
- `reaches(entrypoint, sink)` → reachability (Gate 1, trace)
- `attacker_controls(source, node)` → attacker-control (Gate 2a)
- `no_path(source, sink)` → disproof receipt (`structural-index:no-path`)
- `control_covers(node)` → security-control-on-path (from sec-design)
- `in_attack_surface(entrypoint)` → external-reachability
- `unresolvable(node)` → dynamic dispatch / reflection / config-wired → route to runtime

## 4. Artifact lifecycle: draft → refine → reconcile

Each analysis artifact is a living document with three checkpoints, so it both drives
recall early and ships accurate late.

- Draft (Understand stage): built from architecture KB + Tier-1 substrate facts.
  Gated (`phase_gate` + `phase-adversary`). Claims tagged by kind:
  `code-fact` | `control-to-refute` | `accepted-risk` | `threat-hypothesis`.
  Drives forward: hunt list, investigate candidates, controls to refute.
- Refine (post-prefilter): reconciled against Tier-2 taint reachability. Threats marked
  reachable/unreachable by receipt. Cheap LLM merge + `phase_gate` re-check.
- Reconcile (report): early claims overwritten/annotated with confirmed-finding evidence
  and receipts. `threat-hypothesis` + matching confirmed finding → CONFIRMED (F-id,
  receipt); claimed control refuted by investigate → CONTROL INEFFECTIVE (F-id);
  attack-tree node with a confirmed leaf → likelihood upgraded from guess to evidence.
  The rendered deliverable carries provenance per claim: deterministic-receipt vs
  LLM-judgment vs confirmed-finding.

Guardrail: code analysis augments and corroborates artifacts; it never bounds them. The
LLM+architecture reasoning still drives breadth (logic/authz/business-logic threats SAST
cannot see — see `references/DETECTION_COVERAGE.md`). Deterministic analysis raises
confidence and adds grounded threats on top.

## 5. Per-phase matrix

Legend: D = deterministic method/tool · L = LLM role · A = adversarial review ·
consumes → produces. NEW/CHANGED marked; unmarked phases keep current behavior + the §2
invariants.

### Setup
- 0 Preflight — D: `preflight` verifies tooling + CodeQL packs. → pass/fail.
- 1 Begin pass — D: `state.begin_pass` pins SHA. → `state.json`.

### Understand (artifacts born here)
- Tier-1 substrate pass (NEW, no LLM) — D: `structural_index` + `ast-grep` + `osv` +
  `secrets` + `crypto_policy`. → `kb/graph.json` v1.
- C1 Context-ingest — L: distill repo docs (untrusted). A: context-adversary.
  → `kb/context.json`.
- 2 Recon — D: rg indicators + graph.json facts. L: classify langs/frameworks/surface.
  A: phase-adversary. → `kb/scan-profile.json`.
- 3 Architecture + sec-design (NEW) — D: `structural_index` → C4 node/edge projection;
  `phase_gate` resolves file:line. L: component responsibilities, business/security
  posture, security-controls-per-element, accepted-risks. A: phase-adversary; each
  claimed control tagged `control-to-refute`, each accepted-risk tagged `accepted-risk`.
  → `architecture.md`, `entities/*.md`, `kb/sec-design.md` (C4 diagrams + posture).
- 4 Threat model (RICHER) — D: `reachability.py` (entrypoint→sink); `osv` (supply-chain);
  CI/IaC file presence (build). L: Application/Deployment/Build sub-models, assets,
  data-flows-crossing-boundaries, hunt list. A: phase-adversary.
  → `THREAT_MODEL.md` v1, `kb/attack-surface.md`, `kb/attack-tree.md`.
- Phase gate — D: `phase_gate` (file:line resolves) on all four artifacts. A: opus
  adversary. → `kb/gates/*.json`.

### Detect
- 0.5 Tune (optional) — rule/exclusion ratchet, ≤3 rounds.
- 5 Prefilter (Tier-2) — D: `semgrep` + `codeql` taint → candidates; adds dataflow edges.
  → candidates, `kb/graph.json` v2.
- Threat model v2 (NEW checkpoint) — D: reconcile TM + attack-tree against codeql
  reachability (reachable/unreachable by receipt). L: cheap merge. A: `phase_gate`
  re-check. → `THREAT_MODEL.md` v2 (investigate consumes this).

### Investigate & Confirm
- 6 Investigate — D: query graph.json for reachability (Gate 1) + attacker-control
  (Gate 2a) instead of re-tracing; skip surfaces not in `attack-surface.md`. L: exploit
  reasoning; refute claimed controls at Gate 2b. A: gate ladder (each rung needs a
  receipt). Consumes TM v2, attack-surface, sec-design (accepted-risks → seed candidates,
  controls → refute). → findings anchored to graph nodes.
- Findings gate — D: `findings_gate` receipt check.
- 7 Dedupe — D: `dedupe`.
- 8 Critic / Judge — L: production-viability (consults sec-design controls to refute);
  severity adjudication. A: critic is the adversary.
- 9 Validate — D: `no_path` disproof query (receipt) before spending LLM; consult C4
  boundaries + controls. L: opus tries to refute. A: this is the adversary, different
  family. → confirmed/rejected.
- Trace — D: `reachability.py` verdict; `unresolvable` nodes tagged `needs-runtime`.
  L: reachability interpretation. → static-settled vs needs-runtime.
- 10 Calibrate — D: `cvss` / `calibrate`. → risk_score 1–10.

### Remediate & Deliver
- 11 Patch — L: fix on throwaway copy (consults `codeguard` + mitigations). A: validate-fix
  (security-architect + penetration-tester personas). → patch_diff.
- 12 Verify — D: re-run `semgrep`/`codeql` on patched copy. → verify result.
- 13 Gate — D: `findings_gate`.
- 13.5 Red Team — D: `redteam.py` min-risk filter. L: attack-tree paths → test directives.
  A: redteam-adversary. Consumes attack-tree + attack-surface + needs-runtime
  (graph-unresolvable) findings. → `redteam-plan.md`.
- 14 Report (RECONCILE) — D: overwrite/annotate every analysis artifact's early claims
  with confirmed-finding evidence + receipts; render deliverables. → final `sec-design.md`,
  `threat-model.md`, `attack-tree.md`, `attack-surface.md`, `report.sarif`, `report.md`.
- C2 Postflight — D: `postflight`. → durable `prior_context`.

## 6. Bidirectional evidence (confirm and disprove)

Artifacts raise or lower a finding's confidence; structural disproof carries a mechanical
receipt, so it satisfies the tool-receipt gate rather than being "the LLM changed its
mind."

Corroborate (seed / raise): threat-model hunt-list hit; sec-design accepted-risk;
attack-surface entrypoint.

Disprove (lower / reject), each with a receipt:
- C4 dataflow shows no untrusted path to the component → `structural-index:no-path`.
- Entrypoint not in enumerated attack surface → downgrade to internal-only / needs-runtime.
- Validated security control at file:line covers the sink → candidate false-positive
  unless investigate shows the control is bypassable (Gate 2b).

Safety contract preserved: reasoning-only adversary demotes; only a competing receipt
refutes a receipt-backed finding.

## 7. Red-team plan as terminal catch-basin

`redteam-plan.md` is the static→runtime bridge. In this design the
`static-settled` vs `needs-runtime` split becomes a property of the substrate, not an
LLM judgment: `unresolvable(node)` (dynamic dispatch, reflection, config-wired, external
boundary) routes a finding straight into the plan as a runtime directive. The attack tree
is the plan's precursor — its critical AND/OR paths are the manual test scenarios; a
confirmed leaf → static-settled, an unproven-but-plausible leaf → needs-runtime directive
with the path as the test script. Attack-surface + deployment/build threats populate the
runtime-validation gaps. Nothing unprovable is dropped; it is handed to the human tester
with the path to test it.

## 8. Non-goals / constraints

- No change to the frozen JSON contract or the `go/` tree. If a new artifact needs a
  serialized field on `Finding`/`CampaignState`, coordinate with the Go workstream first
  (see skill CLAUDE.md §1). Prefer new standalone `kb/*.md`/`kb/*.json` artifacts that do
  not touch `models.py`.
- Core stays stdlib-only. New deterministic logic uses existing modules + CLI tools.
- Do not port `xvnpw`'s generator. Adopt its artifact *shapes* (C4 element tables,
  Application/Deployment/Build threat sub-models, attack-tree node attributes), authored
  through our gated phases so every claim is pressure-tested.

## 9. Open questions (resolve during planning)

1. Substrate shape: promote `structural_index` output into a richer `kb/graph.json` with
   an explicit query API, or start with cross-referencing the flat index and formalize
   the graph only for the hottest reuse points (reachability, attacker-control)? Governs
   build size.
2. Should the attack tree and red-team plan be one artifact at two stages, or two linked
   artifacts?
3. Timing of Tier-1 vs recon: run Tier-1 before recon (recon consumes it) or fold Tier-1
   into recon's existing indicator pass?
4. Which new artifacts ship by default vs behind a flag (token cost of the added
   Understand-stage passes)?
