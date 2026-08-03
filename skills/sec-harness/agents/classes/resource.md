# CWE-class extension — resource

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Bound loops/allocations/pagination by attacker-independent limits; canonicalize + confine
paths; stream large inputs. Prove the bound holds under adversarial volume.

## Proof tuple (required evidence)

A confirmable resource finding needs all three, each with a `file:line`:
1. **Attacker-influenced size/path/count** — a size, path, or count parameter under attacker control.
2. **Missing bound/canonicalization** — no upper bound/limit on the value, or no path canonicalization/confinement before use.
3. **Impact** — the concrete consequence (unbounded allocation, path traversal outside the intended root, resource exhaustion).

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
