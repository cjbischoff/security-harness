# CWE-class extension — authz

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Derive identity from the session/token; never trust a client-supplied id for ownership.
Enforce object- and function-level checks on EVERY path.

## Discrimination requirement
Two user contexts: the owner succeeds, a non-owner gets 403/empty. Grep the diff for any
fallback branch that reintroduces the client id.

## Class boundary
**IS:** an authenticated principal reaching another principal's resource, or a
lower-privileged role reaching an action it shouldn't, because the object- or
function-level check is missing or wrong (BOLA/BFLA).
**IS NOT:**
- Whether the caller IS who they claim to be at all → `cls: authn`. Authz assumes
  identity is already established; it governs what an established identity may touch.
- A multi-step workflow invariant (quantity, ordering, state transitions) being violated
  by a legitimate-looking sequence, with no ownership/role check involved → `cls:
  business-logic`.
- A shared AI-agent service credential missing a per-resource re-check on the requesting
  user → `cls: excessive-agency` (same shape, agent-tool context).

## Proof tuple (required evidence)

A confirmable authz gap needs all three, each with a `file:line`:
1. **Protected resource/action** — a concrete resource or action that requires authorization to reach.
2. **Missing/incorrect access check** — no object- or function-level check on the reachable path, or a check that validates authentication but not authorization for this resource.
3. **Attacker-reaching principal** — an attacker-controlled or lower-privileged principal that can reach the unchecked path.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
