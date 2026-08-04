# CWE-class extension — excessive-agency

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Re-check the requesting USER's permission on the specific resource inside every tool
handler — not just that "the agent is allowed to call this tool." Scope service
credentials to the authenticated user's own id.

## Discrimination requirement
A shared service credential that runs every query scoped to the authenticated user's ID
is normal, safe architecture — not a confused deputy. Both halves (no per-resource check
AND an action the user couldn't perform directly) must hold.

## Class boundary
**IS:** an agent tool call that performs a real side effect under a broad/shared
credential without re-checking the REQUESTING USER's authorization for that specific
resource — the confused-deputy shape, specific to agent/tool architectures.
**IS NOT:**
- Untrusted text steering WHICH tool runs or what arguments it gets, with the tool's own
  authz otherwise correct → `cls: prompt-injection`. Excessive-agency is the missing
  per-call authz re-check; prompt-injection is the untrusted-input vector that reaches
  the tool call. The same trace often chains both — if it does, prefer `cls:
  logic-chain` per the base prompt's exception, not one class picking up the other's bug.
- A plain user-facing endpoint (no agent/tool layer) missing an ownership check → `cls:
  authz`.

## Proof tuple (required evidence)

A confirmable excessive-agency gap needs all three, each with a `file:line`:
1. **Agent tool that performs a state change** — a tool call executed under the agent's own identity (service account, broad API key) with a real side effect.
2. **No per-call authz/confirmation re-check** — the handler validates that the tool exists/is callable but not that the requesting user may act on this specific resource.
3. **Attacker influence over tool selection or args** — user-controllable text or parameters steer which tool runs or what it targets.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
