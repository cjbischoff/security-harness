# CWE-class extension — authn

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Verify identity with a server-side, non-bypassable check on every protected path
(constant-time comparison, real session/token validation) before granting access —
never rely on a client-supplied flag or a check that can be skipped.

## Discrimination requirement
A check that validates that a token is PRESENT but not that it is valid/unexpired/
correctly signed is a bypass, not a functioning control — cite the missing validation
step, not just the check's existence.

## Proof tuple (required evidence)

A confirmable authn flaw needs all three, each with a `file:line`:
1. **Identity/authentication decision point** — the code path that is supposed to establish who the caller is (login, session check, token verification).
2. **Bypass or weak-verification path** — a way to reach the protected behavior without a valid identity, or a verification step that doesn't actually check what it claims to.
3. **Unauthenticated/attacker reach** — the bypass is reachable by a party without valid credentials.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
