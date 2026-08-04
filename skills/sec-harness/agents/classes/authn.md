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

## Class boundary
**IS:** a way to reach protected behavior as an unauthenticated party, or with a
forged/expired/unverified identity credential (login bypass, session fixation, JWT
signature not checked).
**IS NOT:**
- An authenticated user reaching another user's data or a role's action → `cls: authz`.
  Authn is only about establishing who the caller is, not what they can then do.
- The password hash or signing algorithm being weak (md5/sha1, no salt, low PBKDF2
  rounds) with the verification FLOW itself otherwise correct → `cls: crypto`. Authn is
  the flow; crypto is the primitive.

## Proof tuple (required evidence)

A confirmable authn flaw needs all three, each with a `file:line`:
1. **Identity/authentication decision point** — the code path that is supposed to establish who the caller is (login, session check, token verification).
2. **Bypass or weak-verification path** — a way to reach the protected behavior without a valid identity, or a verification step that doesn't actually check what it claims to.
3. **Unauthenticated/attacker reach** — the bypass is reachable by a party without valid credentials.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
