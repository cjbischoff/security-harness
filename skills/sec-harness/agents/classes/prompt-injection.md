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

## Proof tuple (required evidence)

A confirmable prompt-injection needs all three, each with a `file:line`:
1. **Untrusted text reaching a model prompt** — a source (retrieval doc, tool response, user text) concatenated into the prompt context without delimiter separation.
2. **Model output flowing to a sink without mediation** — model-emitted text or arguments reaching exec/db/fetch/tool-call unvalidated.
3. **Attacker-controllable source** — the untrusted text or the sink's downstream effect is reachable/influenceable by an attacker.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
