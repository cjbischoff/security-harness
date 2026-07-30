# CWE-class extension — config

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Test contract (no Python TDD)
Config/IaC fixes are verified by a `tfsec`/`checkov` before/after diff where available:
the flagged rule fires before and is gone after.
