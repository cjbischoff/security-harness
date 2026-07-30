# CWE-class extension — injection

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Parameterized query / argument-vector exec / contextual output encoding.

## Discrimination requirement
Replay the SAST/PoC payload verbatim against the fixed code; the fix is only FULL if the
same payload no longer reaches the sink (pre=fail/post=pass).
