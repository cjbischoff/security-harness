---
rule_id: codeguard-0-authorization-access-control
description: Authorization & access control
languages: [python, javascript, typescript, php, go, java, ruby]
always_apply: false
---
## Authorization & access control

- Enforce object- and function-level authz on every request against the authenticated principal.
- Never trust a client-supplied id for ownership; derive identity from the session/token.
- Fail closed; deny by default; centralize checks.
