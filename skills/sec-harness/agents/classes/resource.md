# CWE-class extension — resource

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Bound loops/allocations/pagination by attacker-independent limits; canonicalize + confine
paths; stream large inputs. Prove the bound holds under adversarial volume.
