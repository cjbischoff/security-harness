# CWE-class extension — business-logic

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Enforce the workflow invariant server-side at every step that can mutate state — never
rely on client-side ordering, hidden fields, or UI affordances to keep the sequence
correct.

## Discrimination requirement
A sequence a legitimate user could also trigger by mistake, with no attacker benefit
beyond what they already have, is not a finding. The violated invariant must produce a
concrete, attacker-favorable outcome (double-spend, privilege gain, price/quantity
manipulation).

## Proof tuple (required evidence)

A confirmable business-logic gap needs all three, each with a `file:line`:
1. **Invariant the workflow must hold** — a concrete rule the system depends on (e.g. "quantity can't go negative", "payment precedes shipment").
2. **State/step sequence that violates it** — a code path where steps can be skipped, reordered, or repeated to break the invariant.
3. **Attacker-reachable trigger** — the violating sequence is reachable by a party with attacker-level access, with a concrete benefit.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
