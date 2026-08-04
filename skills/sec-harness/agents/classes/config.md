# CWE-class extension — config

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Test contract (no Python TDD)
Config/IaC fixes are verified by a `tfsec`/`checkov` before/after diff where available:
the flagged rule fires before and is gone after.

## Class boundary
**IS:** an insecure default or exposed setting in configuration/IaC (open ACL, debug
mode on, permissive CORS, exposed port/service) — the weakness lives in the
configuration, not in application code logic.
**IS NOT:**
- A literal credential/API key/token value committed in config or code → `cls: secrets`.
  Config is about a setting being too permissive; secrets is about a value that
  shouldn't be there at all.
- Weak crypto parameters set via config (e.g. a config-driven KDF round count) → `cls:
  crypto`, since the mechanical policy gate lives there.

## Proof tuple (required evidence)

A confirmable config finding needs all three, each with a `file:line`:
1. **Insecure default or exposed setting** — a concrete setting/default that weakens a control (open ACL, debug mode, permissive CORS, exposed port).
2. **Reachability/exposure** — the setting is actually reachable or exposed on the deployed surface, not overridden elsewhere or gated behind an unreachable environment.
3. **Resulting capability** — the specific capability an attacker gains from the exposure (read access, code execution, bypassed auth).

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
