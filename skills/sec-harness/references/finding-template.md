# Verified Finding Template

The canonical shape for a human-facing sec-harness finding. Every confirmed
finding renders these sections. The harness is **static-only** (it never executes
the target), so *by default* every finding is "static analysis only — not
dynamically confirmed": mark the **Confirmation** and **Confirmed Attack Scenario**
sections accordingly and complete all other sections from source analysis. If a
separate dynamic phase runs, upgrade those two sections with reproduction evidence.

## Field bindings (render from the Finding JSON)

This template is the *view* of a `Finding` record — populate it from the fields so
the prose never drifts from the data:

| Section | Finding fields |
|---|---|
| Summary | `cls`, `file:line`, `message` |
| Mechanism | `dataflow`, `evidence`, `file:line` |
| Confirmation | `evidence_sources` (tool receipts vs `llm-claimed:*`), `verification` |
| Impact | `cls`, `cvss_vector` |
| Severity Rationale | `cvss_vector` + computed `risk_score` |
| Confirmed Attack Scenario | `dataflow` |
| Fix | `patch_diff` |
| Testing | `verification` result + `patch_diff` |

## Depth tiers (signal-over-noise applies to reports too)

- **Critical / High** → full 9-section template.
- **Medium / Low** → condensed: Summary, Mechanism, Severity Rationale, Fix.
- **Duplicates** (`duplicate_of` set, or siblings sharing a root cause) → render the
  primary in full and list the sibling `file:line`s under Mechanism; never repeat
  all 9 sections per instance.

## Triage line (skim layer — render first)
One row per finding, strictly risk-ordered (by `_risk_sort_key`: risk desc → severity → id) — so
higher-risk needs-runtime leads surface above lower-risk dep CVEs, without a hard status-first rule:
`ID · Risk · what (one clause of message) · file:line · status (confirmed | needs-runtime) · next action`.
A reader opens this first and expands into the detail views below on demand.

## NDT-view (needs-deployment-testing findings)
Condensed, always labeled **needs runtime proof**, never described as confirmed. Bindings:
| Part | Finding fields |
|---|---|
| What | `message`, `file:line` |
| Source-side chain | `dataflow` |
| Preconditions (out-of-repo barrier) | `preconditions` |
| Runtime test | `runtime_test.objective` + `expected_signal.secure/insecure` |
Runnable payloads + telemetry live in `redteam-plan.md`; the view links there.

## Dep-view (`cls == deps`)
Dependency findings do not use the source-flow sections. Bindings:
| Part | Finding fields |
|---|---|
| Package | `evidence` (`package@version`) |
| Advisory | `rule_id` / `evidence_sources` (OSV id) |
| Reachability | `reachability.reachable` + `reachability.blocker` |
| Fix | bump the package to a release resolving the advisory |

Depth-tiers note: the condensed (Medium/Low) tier **renumbers 1–4** (Summary, Mechanism,
Severity, Fix) — it does not preserve the full-tier section numbers, so no gaps leak into the view.

---

## 1. Summary
What the vulnerability is (class, affected component, scope of impact); where it
exists (feature, endpoint, function, code path); preconditions (auth state, role,
access level); how it is triggered (user action, API call, input manipulation);
what trust boundary or invariant is violated.

## 2. Mechanism (confirmed in source)
Source-level root-cause analysis: cite specific `file:line`s; trace data flow from
attacker-controlled input to the vulnerable behavior; identify the check/gate/
validation that is missing, bypassed, or insufficient; explain **why** the defect
exists structurally, not just symptomatically; reference the query/schema/API
contract if relevant; show the vulnerable code inline. For duplicates, list the
sibling instances here.

## 3. Confirmation
Evidence of the trace, keyed to receipts:
- **Static (default):** the complete source-to-sink trace and why the path is
  reachable. List the **mechanical tool receipts** grounding it
  (`semgrep:`/`codeql:`/`ast-grep:`/`ripgrep:`/`structural-index:`/`secrets:`/`sca:`).
  For SAST-blind template languages, a `ripgrep:` receipt proving the unescaped
  interpolation at `file:line` is the mechanical ground. A finding resting **only**
  on `llm-claimed:*` is not confirmable — say so and downgrade to a lead.
- **Dynamic (if a dynamic phase ran):** exact reproduction steps, environment,
  timestamp, method (curl/browser/script); stored artifacts with workspace paths
  (HAR, screenshots, request/response pairs); a **control test** (same action
  without the exploit condition) proving it is genuine, not a false positive.
- **Unverifiable external boundary:** if the sink crosses into code not in this
  repo (a SaaS API, an unvendored package), state the boundary explicitly and what
  is confirmed on this side vs. left as a mitigating unknown — never launder the
  unknown into either a confirmation or a rejection.

## 4. Impact
Business + technical: what data/systems/operations are affected; scope (single
user, single tenant, cross-tenant, catalog-wide, unbounded); CIA assessment
(Confidentiality/Integrity/Availability); whether it is repeatable, scriptable, or
one-shot.

## 5. Severity Rationale
- Propose a **CVSS 3.1 vector**; the harness computes the numeric **score**
  deterministically — never assert a score by hand.
- Justify each metric choice (AV, AC, PR, UI, S, C, I, A).
- Justify the band (Critical/High/Medium/Low).
- **When a precondition or delivery vector is unproven (only `llm-claimed`),
  choose the LOWER tier** and say why (e.g. CSRF delivery unconfirmed → hold at
  Medium).
- Note compensating controls that raise or lower effective risk.

## 6. Confirmed Attack Scenario
Preconditions the attacker needs; numbered steps (API calls, payloads, UI
interactions); expected vs. observed behavior per step; concrete harm. For
static-only findings, mark this "theoretical — not dynamically confirmed" and give
the reasoned path.

## 7. Fix
- Numbered steps if multiple files/changes.
- Per change: exact `file` path, current (vulnerable) block, fixed block.
- New dependencies/schema/config required.
- If multiple strategies exist, recommend one with the tradeoff.
- **Why this fixes it:** connect to the root cause; name the invariant/check
  introduced; explain why the attacker can no longer reach the sink; state any
  residual risk the fix does not address.

## 8. Testing and Verification
- Unit/integration tests: inputs, expected outputs, assertions; reference existing
  suites/frameworks.
- **Negative test:** the original exploit path must now return the expected
  rejection (403, validation error, empty result).
- **Regression test:** legitimate use still works.
- Manual verification steps if automated tests are insufficient.
- The harness's own static check: after the patch, the finding's detector rule
  (`evidence_sources`) must no longer fire in the file (`verification:
  verified-static`).

## 9. Open Questions for Engineering (optional)
Only when genuine implementation questions exist: config choices engineering must
make; environmental factors not verifiable during analysis; edge cases warranting
further investigation. (Keep the *unverifiable external boundary* in §3, not here —
that is a confirmation caveat, not an engineering question.)
