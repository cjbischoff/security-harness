# sec-harness: KB doc redesign, mermaid diagrams, and process hardening

**Status:** approved, pending implementation plan
**Origin:** findings from a full audit run against `agent-gateway` (see `AUDIT-EVAL-agent-gateway.md`), reviewed and expanded through brainstorming with the user.

## Problem

A full 14-phase + loop-until-dry audit run against a real target surfaced two categories of issue:

1. **KB documents overlap instead of giving distinct views.** `THREAT_MODEL.md`'s own prompt instructs it to restate `architecture.md`'s trust boundaries "crisply" — by design, not by accident. `CONTEXT.md` mixes structural claims with doc-vs-reality claims. All three are dense prose with no visual structure, making them harder for a human to actually use than they need to be.
2. **Several harness-process gaps**, found and manually corrected during the run, that should be fixed upstream instead of re-discovered by an adversary every time: a reproducible `verify.py` bug, agents writing into fields outside their phase's remit, a citation-acceptance gap that lets "PRESENT granted on a comment" through, a recurring blanket-qualifier failure pattern across producer agents, a missing deployment-config context source, and no structured way to surface "this needs a human to answer a question" separately from "this needs a live exploit test."

Not in scope: target-specific findings about `agent-gateway` itself (those are for its owners), and the workspace-slug-naming issue (confirmed to be an execution error this session, not a skill defect — `repo_memory.repo_slug()` already does this correctly).

## Design

### 1. Doc lens redefinition

Each KB doc's producing agent gets a rewritten Output section stating one distinct lens, so content can't drift back into overlap:

- **`context-ingest.md` → `CONTEXT.md`**: "what the repo claims about itself, and whether that claim holds." Purely `kind: trust_boundary | claimed_control | prior_finding | attack_lead | deployment_config` items with `verify_status`, rendered as tables. No structural/component prose — that belongs to architecture.md.
- **`architecture.md`**: the single canonical source for structural facts (components, data flows, trust boundaries). Other docs reference it; none restate it.
- **`threat-model.md` → `THREAT_MODEL.md`**: drop the "restated crisply" trust-boundary section entirely. Replace with a pointer to `architecture.md` plus attacker-relevant annotations only (e.g. "boundary X is where profile Y's access ends"). The doc's real content is attacker profiles + prioritized hunt list.

### 2. Mermaid diagrams — sequenced, capped, per-doc

Diagrams are **first-class and multiple per doc**, not a fallback for when prose gets too dense. Each diagram has exactly one job, stated in a one-line caption. **Hard cap: 10 entities (nodes + subgraphs) per diagram** — a view that needs more entities becomes a second diagram in the sequence, not a shrunk-label version of the same diagram.

| Doc | Diagram 1 | Diagram 2 | Diagram 3 |
|---|---|---|---|
| `architecture.md` | Component overview (subsystems + call edges) | DFD — data flow per entrypoint to its sinks | Trust-boundary diagram (subgraphs = boundaries; the one canonical version referenced by other docs) |
| `CONTEXT.md` | Claimed-control status map (`verify_status` grouped by trust boundary) | *(second only if >10 controls)* | — |
| `THREAT_MODEL.md` | Attacker-profile → entrypoint reachability | Traditional threat diagram (STRIDE-style) for the top hunt-list item(s) — a genuinely different shape from the DFD, not a restatement | — |

Style rule (new shared block in `prompt-constants.md`, imported by all three producing agents): short node IDs/labels; detail goes in a legend or edge label, never crammed into a node; diagrams never carry file:line citations themselves — prose remains the citable source of truth, diagrams are the navigational/summary layer.

**No new adversary infrastructure.** The existing `phase-adversary.md`/`context-adversary.md` prompts get one added bullet: if a diagram contradicts a prose claim already under review, flag it exactly like any other claim (WEAKENED/INVALIDATED). Reuses the existing gate rather than inventing a diagram-specific verifier.

### 3. Process-hardening fixes

- **Verify.py false-fixed bug.** For `deps`/SCA-class findings, `sec_harness.verify`'s deterministic re-scan currently promotes to `fixed` on an OSV text-match alone, even when the "fix" is a non-functional placeholder version string. Reproduced twice in one campaign (same finding, two separate verify runs), each time silently overwriting a correct, explicit `not_fixed` validate-fix verdict. Fix: (a) reject promotion for `deps` findings unless the bumped version parses as valid semver, and (b) generally, never let a deterministic verify pass silently overwrite an explicit `not_fixed` validate-fix verdict on the same finding — record a `verify:conflict` history entry and leave status as validate-fix left it, surfaced for human review instead of auto-resolved.
- **Field-ownership guard.** New shared prompt-constants block, imported by every phase prompt: "only populate the fields your phase's Output section names; if a field outside your remit (e.g. `reachability`, `runtime_disposition`, `verification`, `risk_score`, `patch_diff`) is already set, leave it for its owning phase." Addresses a repeated leak this run (multiple agents across multiple phases wrote into `reachability`/`runtime_disposition`, caught each time only because the correct downstream phase re-derived and overwrote it).
- **Comment-line citation rejection.** `phase_gate.resolve_ref` gains a check: if the resolved line matches a comment pattern for its language, the citation does not count as code-grounded evidence for a `PRESENT`/confirming claim. Deterministic, no LLM cost — this run hit the "PRESENT granted on a comment" failure 4 separate times across 3 phases before an opus adversary caught each one by hand.
- **Qualifier-proof rule.** New shared prompt-constants block, imported by `context-ingest.md`/`recon.md`/`architecture.md`: any blanket qualifier ("mitigated", "allowlisted", "single chokepoint", "authorized by X") requires demonstrating it holds on every code path checked, not just the first one found; otherwise state the specific path(s) checked instead of the blanket claim.

### 4. New context source — deployment/IaC config

`context.py` gains a new discovery glob set covering common IaC tooling generally (not just the Pulumi shape that broke on this run): `Pulumi.*.yaml`, `*.tfvars`/`terraform.tfvars`, Helm `values*.yaml`, `k8s/*.yaml`, `docker-compose*.yaml`, `serverless.yml`. New `ContextItem` kind: `deployment_config`. Each `claimed_control` gains an optional `deployed_in` field (which environments it's actually active in). `context-ingest.md`'s procedure adds a step: cross-check any claimed_control against these files before setting `verify_status` — this is what would have caught, on the first pass, the deployment-flag inversion that took two separate adversary reviews to surface this run.

### 5. Open Questions artifact (new)

Not every unknown a finding surfaces is a live-exploit question. Some are answerable only by a human checking something outside the repo (org policy, a config value, a version range). Today the harness has one mechanism for post-static unknowns (`runtime_test` — a curl-style exploit an operator runs) and no mechanism for "go ask/check this specific thing." This run generated three real examples that had nowhere structured to go (they ended up as prose recommendations in a human-written eval doc instead of harness output): *is there really no Azure AD group-membership check anywhere outside this repo? Is the kubernetes VPC-egress backstop actually deployed? What's the real affected-version range for the x/crypto CVE?*

- New `Finding` field: `open_questions: [{question, why_it_matters, who_to_ask_or_check}]`.
- Populated by **trace** (when a `verify-error` is caused by an external fact, not by "needs a live exploit attempt") and by **redteam** (when the static-settled/needs-runtime discrimination surfaces a question rather than a testable payload). A finding may carry both `runtime_test` and `open_questions`.
- **Quality bar enforced in the prompt, not left to convention**: each question must name a specific person/team/action, not be vague. Bad: *"verify this is safe."* Good: *"Ask the identity/security-platform team: is there an Azure AD group-membership check enforced anywhere outside this repo (e.g. a Conditional Access policy) for the `/mcp` user path? If yes, name it and where it's configured."*
- `redteam-plan.md` gains a new top-level section, **"Questions to ask"**, alongside (not merged into) "Runtime tests to run" — one document, two clearly separated kinds of operator action.

## North star (stated explicitly per user direction)

The measure of success for this whole redesign is **not** "diagrams exist" or "sections are non-overlapping" as ends in themselves. It's: **is the information a human gets from these docs valuable, actionable, and consumable** — not just filled-in-template. Findings must be accurate; where accuracy isn't achievable from source alone, the finding must carry a specific, human-readable next step — either a runnable test or a clearly-posed question — never a bare "unknown" flag with no path forward.

## Out of scope for this design

- Diagrams for `kb/entities/*.md` (stay prose, already scoped tight per existing convention).
- Any new verification infrastructure beyond the one added phase-adversary bullet in §2 — no diagram-specific adversary agent.
- Target-specific fixes for `agent-gateway` (govulncheck run, `errorResult` fencing, etc.) — those belong to that repo's owners.
- Workspace-slug naming — confirmed non-issue, `repo_memory.repo_slug()` is already correct.

## Files touched (for the implementation plan to scope against)

- `agents/context-ingest.md`, `agents/architecture.md`, `agents/threat-model.md` — lens redefinition + diagram instructions.
- `agents/context-adversary.md`, `agents/phase-adversary.md` — one added diagram-consistency bullet each.
- `references/prompt-constants.md` — new `FIELD_OWNERSHIP` and qualifier-proof blocks; new diagram style rule.
- `helpers/sec_harness/context.py` — new IaC globs, `deployment_config` kind, `deployed_in` field.
- `helpers/sec_harness/verify.py` — semver validation for `deps` promotion, conflict-logging instead of silent overwrite.
- `helpers/sec_harness/phase_gate.py` — comment-line citation rejection.
- `helpers/sec_harness/models.py` — new `open_questions` field on `Finding`.
- `helpers/sec_harness/redteam.py` — "Questions to ask" section in `redteam-plan.md`.
- `agents/trace.md`, `agents/redteam.md` — populate `open_questions`.
- READMEs for `agents/`, `helpers/`, `references/` — updated in the same commit per this repo's hard rule (`skills/sec-harness/CLAUDE.md` §8).
