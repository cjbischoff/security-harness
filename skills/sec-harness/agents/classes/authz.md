# CWE-class extension — authz

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Derive identity from the session/token; never trust a client-supplied id for ownership.
Enforce object- and function-level checks on EVERY path.

## Discrimination requirement
Two user contexts: the owner succeeds, a non-owner gets 403/empty. Grep the diff for any
fallback branch that reintroduces the client id.
