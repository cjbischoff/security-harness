---
rule_id: codeguard-0-api-web-services
description: API & web services
languages: [python, javascript, typescript, php, go, java]
always_apply: false
---
## API & web services

- Verify webhook signatures (HMAC over the raw body, constant-time compare) before processing.
- Authenticate + authorize every endpoint; rate-limit; validate content-type.
- Do not reflect unvalidated input into responses/headers.
