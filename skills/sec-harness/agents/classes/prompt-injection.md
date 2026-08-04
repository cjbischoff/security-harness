# CWE-class extension — prompt-injection

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Delimit untrusted spans from control text (role/fencing separation), never concatenate
raw. Treat model output as untrusted input at every sink; validate/parameterize exactly
like a request body before it reaches exec/db/fetch/tool-call.

## Discrimination requirement
Injection that only affects the attacker's own session/output is not a finding. The
injected content must cross a boundary — reach a victim's context, invoke a capability
the requester lacks, or drive a downstream sink the attacker couldn't otherwise reach.

## Class boundary
**IS:** untrusted text (user input, retrieved doc, tool response) altering the model's
behavior because it isn't delimited from control/instruction text.
**IS NOT:**
- The model's output then reaching exec/db/fetch WITHOUT any additional per-call authz
  check on the requesting user → that missing re-check is `cls: excessive-agency`, layered
  on top of (not instead of) the injection vector. Report the injection here and the
  missing re-check under excessive-agency, or as one `logic-chain` if they're the same
  trace.
- Cross-tenant data mixing via an unscoped cache/embedding key with no untrusted-prompt
  component → `cls: context-bleed`.
- The classic exec/db/fetch sink reached via a NON-model-mediated path (plain HTTP
  param straight to `subprocess`) → the concrete technical class (`cmdi`/`sqli`/`ssrf`),
  not prompt-injection.

## Proof tuple (required evidence)

A confirmable prompt-injection needs all three, each with a `file:line`:
1. **Untrusted text reaching a model prompt** — a source (retrieval doc, tool response, user text) concatenated into the prompt context without delimiter separation.
2. **Model output flowing to a sink without mediation** — model-emitted text or arguments reaching exec/db/fetch/tool-call unvalidated.
3. **Attacker-controllable source** — the untrusted text or the sink's downstream effect is reachable/influenceable by an attacker.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
