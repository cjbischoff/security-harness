# Spec B — Multi-Repo Holistic Correlation

**Date:** 2026-08-08
**Status:** design (approved; awaiting user review before writing-plans)
**Supersedes/expands:** `docs/plans/2026-08-07-cross-repo-correlation-design.md` (the seed).
**Depends on:** Spec A Plan 1 (ScanScope — canonical `repo_root`/`scan_scope`/stable slug, `kb/scan-scope.json`), Plan 3 (coverage-ledger, `needs-deployment-testing` in `findings.json`). All merged to `main`.
**Scope:** a read-only correlation layer over N per-repo scans. **Out of scope:** re-scanning member repos; write-back to per-repo findings; any `models.py`/`evidence.py` change.

---

## 1. Goal & success criteria

sec-harness is single-target. A product spanning a solution repo (RBAC defs), service repos
(enforcement), and an infra repo (deployment) produces N independent `.sec-harness/<slug>/`
workspaces with no link. The 4-repo AEM audit proved the highest-value findings are cross-repo by
construction and today live only as prose in a `needs-deployment-testing` "out-of-repo" note. Spec B
makes correlation a first-class capability.

**Success:**
- A `needs-deployment-testing` finding whose out-of-repo barrier lands in an ingested member gets a
  **receipt-backed correlation verdict** (promoted toward confirmed, or demoted to
  rejected/informational) with an explicit `evidence_chain`; a finding whose enforcer repo is NOT in
  the set stays `needs-deployment-testing` and is logged as a `coverage-gap` (never silently resolved).
- Per-repo scan artifacts are **byte-identical before and after** a correlation run (immutability).
- Every LLM-derived cross-repo edge and every promotion is pressure-checked by an independent opus
  cross-repo adversary; **only a deterministic join + a mechanical tool receipt in the resolving repo
  can promote** — cross-repo reasoning alone may demote/weaken, never confirm.
- Four combined artifacts + a cross-repo SARIF are produced, with mermaid diagrams emitted
  deterministically from the edge-graph (never hallucinated).

**Non-success (explicit):** the correlation layer never manufactures a finding the per-repo scans
did not surface; it links, rolls up, and re-thresholds existing findings.

---

## 2. Architecture

New module `sec_harness.correlate` + a `CorrelationWorkspace` dataclass rooted at an `--out` dir that
holds the manifest, the edge graph, verdicts, gate records, and the combined artifacts. It spans
repos, so it is NOT stored inside any member repo's sidecar.

**Product manifest** (`product.json`, lives with the correlation workspace):

```json
{
  "product": "aem-analytics",
  "members": [
    {"slug": "aem-analytics-1eec8d50", "repo_root": "/abs/aem-analytics",
     "scan_scope": ".", "role": "rbac-source"},
    {"slug": "go-<hash>", "repo_root": "/abs/go", "scan_scope": "internal/aemeventservice",
     "role": "service-enforcer"},
    {"slug": "go-<hash>", "repo_root": "/abs/go", "scan_scope": "internal/aemanalytics",
     "role": "service-enforcer"},
    {"slug": "aem-analytics-infra-368b4d0f", "repo_root": "/abs/aem-analytics-infra",
     "scan_scope": ".", "role": "infra"}
  ]
}
```

`role ∈ {rbac-source, service-enforcer, infra}`. Members are located by `repo_root` +
`scan_scope` (→ the sidecar via `RepoMemory.for_target`) — the same identity Plan 1's
`ScanScope`/`repo_slug` produce, so a monorepo sub-service resolves unambiguously.

**Ingest (read-only).** For each member, load `findings/*.json`, `kb/context.json`,
`kb/architecture.md`, `kb/THREAT_MODEL.md`, `kb/scan-scope.json`, `kb/coverage-ledger.json`,
`kb/gates/*`. Every finding gets a **member key** `<slug>#<scan_scope>` and a cross-repo id
`<member-key>:<file>:<line>:<rule_id>`. The `#<scan_scope>` suffix disambiguates two monorepo
sub-services that share a `repo_slug` (the run-log collision: `internal/aemeventservice` and
`internal/aemanalytics` both slug `go-<hash>`) — the manifest may list the same `slug` twice with
different `scan_scope` and the member key stays unique. Ingest opens no member file for write. CLI:
`python -m sec_harness.correlate --manifest product.json --out <dir>`.

---

## 3. Cross-repo edge graph (deterministic-first)

A typed edge: `{type, from: <cross-repo-ref>, to: <cross-repo-ref | symbol | proto-rpc>, join:
"deterministic"|"llm", evidence, confidence}`. Edge types:

- **`shared-dependency`** — same OSV id in ≥2 members' `deps` findings. Pure join; rolls N findings
  into one with a per-repo reachability list (a lockfile-only member stays low). No LLM.
- **`contract-consistency`** (the money lattice) — join `rbac-source` privilege strings (from that
  repo's `src/rbac` findings / context) against `service-enforcer` `.proto` RBAC attributes + gRPC
  service attributes. Verdicts: privilege defined but no proto RPC references it → dead/undefended;
  proto RPC requires a permission absent from `rbac-source` → enforcement without a grantable
  privilege; `isTaaSInternal`/content-set mismatch between the two. Deterministic string join.
- **`same-class-recurrence`** — same `cls` + refactor-resistant fingerprint shape in ≥2 members →
  `systemic` tag + priority bump. Deterministic.
- **`control-enforces`** — a `claimed_control`/authz-def finding in one member ↔ the handler/proto in
  another that must enforce it. Deterministic where names match (privilege string ↔ proto attr);
  LLM only for the ambiguous residue.
- **`trust-boundary-stitch`** — a member's trust boundary whose `where` names an out-of-repo target
  resolves to another member's entrypoint (match on service name / proto package / route).
  Deterministic where names match; LLM for the residue.

The graph is written to `correlation/edges.json`. `join: "llm"` edges carry `confidence` and MUST
pass the §5 adversary before they inform any verdict or artifact.

---

## 4. Re-thresholding engine (the core)

For each member finding with `status == needs-deployment-testing` (and its logged out-of-repo
barrier), the engine asks: does an edge land that barrier inside an ingested member?

**Resolution rules (deterministic; each requires a mechanical receipt in the *resolving* repo):**
- Barrier proven **absent** — the resolving member carries a mechanical receipt that the expected
  control does not exist (e.g. the `.proto` RPC has no RBAC attribute; the handler has no MR /
  content-set check; the entitlements config binds no partition) → **promote** the finding's
  correlated status toward `confirmed`.
- Barrier proven **present** — the resolving member carries a receipt of the control (the check
  exists on the path) → **demote** to `rejected`/`informational` (compensating control found).
- **Systemic** — a `same-class-recurrence` edge for a confirmed/NDT finding raises priority (never
  lowers).
- Resolving member **not in the manifest** → status unchanged (`needs-deployment-testing`), emitted
  as a `coverage-gap` in the report with the missing member named.

**The correlation verdict object** (`correlation/verdicts.json`, one per re-thresholded finding):

```json
{"finding_ref": "<slug>:<file>:<line>:<rule_id>", "base_status": "needs-deployment-testing",
 "correlated_status": "confirmed" | "rejected" | "informational" | "needs-deployment-testing",
 "direction": "promote" | "demote" | "systemic" | "coverage-gap",
 "edge": "<edge id>",
 "evidence_chain": ["<slug>:<file>:<line> — <mechanical receipt>", ...],
 "confidence": "high|medium|low", "adversary": "confirmed|weakened|invalidated"}
```

**Hard rules:**
- The engine **never writes to any member's `findings/`** — verdicts live only in the correlation
  workspace. A member re-run reproduces its own artifacts byte-for-byte.
- Promotion to `confirmed` requires `join: "deterministic"` on the resolving edge AND ≥1
  `evidence.is_tool_receipt` source in the resolving member. Cross-repo context satisfies a
  *precondition*; it never substitutes for the receipt. An `llm`-join edge can support a `demote`
  (caution) but never a `promote` to confirmed.
- A verdict inherits the **lower** confidence of its two endpoints.
- Base status is always preserved alongside `correlated_status` so the provenance is auditable.

---

## 5. Adversary gate

New `agents/cross-repo-adversary.md` (opus, fresh context, independent of any producer). It reviews:
(a) every `join: "llm"` edge — is the link real in both repos' code, or a coincidental name match?
(b) every `promote` verdict — does the deterministic join hold AND is the cited resolving-repo receipt
genuine and mechanical? It applies `confirmed | weakened | invalidated` per edge/verdict; a promotion
survives only on `confirmed`. Reasoning alone may weaken/invalidate (demote) but never upgrade a
verdict. Records to `correlation/gates/`. Same model-family-diversity contract as the rest of the
harness (opus adversary vs the producer; single-family → fresh-context + log).

---

## 6. Combined artifacts

**Deterministic mermaid** (emitted by code from `edges.json`, golden-tested):
- `component-graph` — nodes = members (by role) + shared services + trust boundaries; edges =
  `trust-boundary-stitch` + `contract-consistency`. Embedded in the architecture doc.
- `attack-chain-graph` — source→sink paths that cross repos (`control-enforces` + `attack-chain`),
  each node a `<repo>:<file:line>`. Embedded in the threat-model + red-team docs.

**Combiner agent** (`agents/correlate-combiner.md`, sonnet) writes the narrative for four docs, each
then opus-adversary-gated; diagrams are injected by code, not authored by the agent:
- `correlation/ARCHITECTURE.md` — how the product's repos compose (data flow, trust boundaries,
  shared services); embeds `component-graph`.
- `correlation/THREAT_MODEL.md` — attacker profiles that span repos (a DataBus participant, a
  console user, a compromised CI) + the stitched trust boundaries; embeds `attack-chain-graph`.
- `correlation/REDTEAM.md` — cross-repo manual test directives, prioritizing systemic classes and
  stitched attack chains; each directive cites the verdict + evidence chain; `$SHELL_VAR` payloads,
  never literal secrets.
- `correlation/FINDINGS.md` — the correlated findings: promoted/demoted verdicts with provenance,
  rolled-up shared CVEs, systemic classes, and the explicit `coverage-gap` list (out-of-repo
  barriers whose enforcer repo was not ingested).

**`correlation/report.sarif`** — a multi-`runs[]` SARIF: one run per member (its confirmed/fixed
findings) + one correlation run (promoted verdicts). Demoted/NDT verdicts are notes, not results.

All artifacts under `--out`. Nothing written into a member repo.

---

## 7. Decomposition into plans (build order)

- **B-Plan 1 — correlation core (deterministic, no LLM).** Manifest schema + `CorrelationWorkspace`
  + read-only ingest + `shared-dependency` roll-up + `contract-consistency` lattice +
  `same-class-recurrence`. Writes `edges.json`. Immediate value; fully unit-testable.
- **B-Plan 2 — re-thresholding engine + fuzzy edges + adversary.** `control-enforces` /
  `trust-boundary-stitch` (deterministic + llm residue), the promote/demote engine,
  `verdicts.json`, `agents/cross-repo-adversary.md`, the gate records.
- **B-Plan 3 — artifacts.** Deterministic mermaid emitters + `agents/correlate-combiner.md` + the 4
  docs + cross-repo SARIF.

Each plan produces working, independently testable software (B-Plan 1 already yields shared-CVE
roll-up + the contract lattice verdicts).

---

## 8. Testing

TDD throughout, reusing the 4-repo AEM audit sidecars as a fixture corpus (they carry real
`needs-deployment-testing` findings with out-of-repo notes):
- Deterministic joins: exact unit tests — privilege↔proto match/miss, OSV roll-up + per-repo
  reachability, fingerprint recurrence.
- Re-thresholding truth table: barrier-absent→promote (with receipt) / barrier-present→demote /
  enforcer-absent→coverage-gap / llm-join→never-promote. Assert source findings are untouched
  (byte-compare before/after).
- Mermaid emitters: golden-string tests from a fixed edge-graph.
- Combiner + adversary: contract/wiring tests (prompt↔schema drift), like the existing
  `test_contracts.py`/`test_wiring.py`.

---

## 9. Non-goals / YAGNI

- No re-scanning of member repos — ingest only.
- No write-back to per-repo `findings/` — correlation verdicts are their own layer.
- No new `FindingStatus`/`Severity` and no `models.py`/`evidence.py` change → no Go-golden regen.
  (`CorrelationVerdict` is a new correlation-only dataclass, not part of the frozen contract.)
- No membership auto-discovery — the manifest is explicit.
- Mermaid-in-markdown only; no image rendering.
- No cross-product correlation (one manifest = one product).
