# Cross-repo correlation — feature design

**Status:** design (from live need during the AEM 4-repo campaign, 2026-08-07)
**Problem:** sec-harness is single-target. A product spanning a solution repo (RBAC defs), two
eng/go services (enforcement), and an infra repo (deployment/entitlements) produces four
independent `.sec-harness/<slug>/` workspaces with no link between them. The highest-value
findings are *cross-repo by construction*: an RBAC privilege defined in repo A is enforced (or
not) by a handler in repo B, wired by entitlements in repo C. Today that correlation is done by
hand in the main agent. This designs a first-class capability.

## What the campaign proved we need (evidence)

Concrete cross-repo links already surfaced, each currently living only as prose in a
`needs-deployment-testing` finding's "out-of-repo" note:

1. **Control→enforcement handoff.** aem-analytics `AUTHZ-0001/0002`, `CTL-0001/0002` (privilege
   defs in `src/rbac/spec.js`) are all "enforcement is in eng/go `internal/aemanalytics`" — they
   are *verification tasks* for campaign 3, not standalone results.
2. **Recurring class = systemic.** CE-ID-from-payload (aem-event-service `CTL-0001`) is the exact
   Tanium cross-tenant pattern; if `internal/aemanalytics` shows the same shape it's systemic, not
   a local slip — a materially higher finding.
3. **Shared dependency CVEs.** Each repo's OSV scan is isolated; the same vulnerable package
   across repos should roll up once with per-repo reachability.
4. **Trust-boundary stitching.** aem-analytics trust boundary "console→module API (out-of-repo)"
   is the *entrypoint* of the go service; infra wires the entitlements both assume.

## Design

### 1. Correlation workspace (aggregator)
A new workspace type `CorrelationWorkspace` that ingests N per-repo memory folders (paths or
slugs) read-only and writes its own `correlation/` artifacts. No re-scan; it joins existing
`findings/`, `kb/context.json`, `kb/THREAT_MODEL.md`, `kb/architecture.md`, `kb/gates/`.
CLI sketch: `python -m sec_harness.correlate --repos <slugOrPath>... --out <dir>`.

### 2. Cross-repo finding identity + edges (deterministic-first)
Add a `cross_repo` edge model. An edge is `{type, from: <repo:finding>, to: <repo:finding|symbol|proto>, evidence, confidence}`. Edge types:
- `control-enforces` — a `claimed_control` / authz-def finding in repo A ↔ the handler/proto in
  repo B that must enforce it. **Join key:** privilege name / proto RPC / permission string
  (deterministic string match on `auth.proto` permission ↔ `src/rbac` privilege name), then LLM
  semantic link for the fuzzy cases, adversarially validated.
- `shared-dependency` — same `(package, version-range, CVE)` in ≥2 repos' `deps` findings.
  Pure deterministic join on OSV id. Rolls N findings into one with a per-repo reachability list.
- `trust-boundary-stitch` — repo A boundary whose `where` names an out-of-repo target resolves to
  repo B's entrypoint (match on service name / proto package / route).
- `attack-chain` — a `needs-runtime` lead in A (source) composes with a confirmed sink in B.
- `same-class-recurrence` — same `cls` + same code shape (fingerprint) in ≥2 repos → tag
  `systemic`, bump priority.

### 3. Contract-consistency checks (the money feature)
A deterministic lattice built from the two authoritative sources the Tanium ref calls out:
`src/rbac/` privilege/role defs (solution repo) and `pkg/rbac/auth.proto` + gRPC service
attributes (eng/go). For each privilege:
- defined in `src/rbac` but **not referenced** by any proto RPC attribute → dead/undefended priv.
- required by a proto RPC but **absent** from `src/rbac` → enforcement without a customer-grantable
  privilege (or vice-versa) → authz gap.
- flag mismatches (`isTaaSInternal`, content-set scoping) between the two sources.
This turns campaign 1's `CTL-0001/0002` and `AUTHZ-0002` from "needs-runtime, verify in eng/go"
into a *mechanical cross-repo verdict* the moment both repos are ingested.

### 4. Monorepo-aware dedupe
Two service targets under one eng/go monorepo share `pkg/` code. A finding in shared `pkg/` code
surfaced by both service scans must dedupe to one (join on absolute file:line + fingerprint),
attributed to both consuming services. (Also fixes the `repo_slug` collision noted in the run log.)

### 5. Systemic-vs-local classification + report
Correlation report (`correlation/REPORT.md` + a cross-repo SARIF `runs[]` array): sections for
(a) contract-consistency verdicts, (b) systemic classes (≥2 repos), (c) rolled-up shared CVEs,
(d) stitched attack chains, (e) unresolved cross-repo handoffs (a needs-runtime lead in A whose
enforcer repo B was NOT ingested → explicit coverage gap, never silently dropped).

### 6. Adversarial + determinism guarantees (inherit the harness contract)
- Deterministic-first joins (string/CVE/fingerprint) are the backbone; LLM only for fuzzy
  semantic links (`control-enforces`, `trust-boundary-stitch`).
- Every LLM-derived cross-repo edge is pressure-checked by an independent opus adversary
  (`cross-repo-adversary.md`) before it enters the report — same safety contract: reasoning
  weakens/drops an edge, only a mechanical join (matching permission string / CVE id / fingerprint)
  confirms one.
- A cross-repo finding inherits the *lower* confidence of its endpoints; an edge whose target repo
  was never scanned is a `coverage-gap`, not a finding.

## Minimal first slice (build order)
1. `shared-dependency` roll-up (pure deterministic OSV join) — immediate value, no LLM.
2. Contract-consistency lattice `src/rbac` ↔ `auth.proto` (deterministic string join) — turns the
   current campaign's biggest hand-waved handoffs into verdicts.
3. `control-enforces` semantic edges + adversary gate.
4. Correlation report + cross-repo SARIF.
Chains/systemic tagging (4/5) fall out once edges exist.
