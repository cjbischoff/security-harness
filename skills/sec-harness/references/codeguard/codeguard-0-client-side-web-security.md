---
rule_id: codeguard-0-client-side-web-security
description: Client-side web security
languages: [javascript, typescript, html]
always_apply: false
---
## Client-side web security

- Never assign untrusted data to innerHTML/document.write/dangerouslySetInnerHTML; use textContent or a sanitizer.
- Validate postMessage origin; set CORS explicitly (no credentialed wildcard).
- Avoid client-side redirects to attacker-controlled URLs / javascript: schemes.
