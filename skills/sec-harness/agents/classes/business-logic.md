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

## Class boundary
**IS:** a workflow/state-machine invariant broken by skipping, reordering, or repeating
steps a legitimate user is otherwise allowed to take.
**IS NOT:**
- Reaching another user's resource or a higher-privileged action because an
  object-/function-level check is missing → `cls: authz`. Business-logic assumes the
  attacker is acting within their own account/role; the bug is in the sequence, not the
  permission check.
- A raw SQLi/XSS/path-traversal/deserialization sink reachable from input, even if it
  happens to sit inside a business workflow → file it under the concrete technical
  `cls`, not `business-logic`. Reserve this class for sequence/invariant violations a
  scanner-shaped class can't express.

## Proof tuple (required evidence)

A confirmable business-logic gap needs all three, each with a `file:line`:
1. **Invariant the workflow must hold** — a concrete rule the system depends on (e.g. "quantity can't go negative", "payment precedes shipment").
2. **State/step sequence that violates it** — a code path where steps can be skipped, reordered, or repeated to break the invariant.
3. **Attacker-reachable trigger** — the violating sequence is reachable by a party with attacker-level access, with a concrete benefit.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
