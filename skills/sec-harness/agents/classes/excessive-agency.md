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

## Proof tuple (required evidence)

A confirmable excessive-agency gap needs all three, each with a `file:line`:
1. **Agent tool that performs a state change** — a tool call executed under the agent's own identity (service account, broad API key) with a real side effect.
2. **No per-call authz/confirmation re-check** — the handler validates that the tool exists/is callable but not that the requesting user may act on this specific resource.
3. **Attacker influence over tool selection or args** — user-controllable text or parameters steer which tool runs or what it targets.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
