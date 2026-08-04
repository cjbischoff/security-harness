---
rule_id: codeguard-0-cryptography
description: Cryptography
languages: [python, javascript, typescript, php, go, java]
always_apply: false
---
## Cryptography

- Use authenticated encryption (AES-GCM / libsodium); never unauthenticated CTR/CBC or ECB.
- Never MD5/SHA-1/DES for security; use SHA-256+ and a slow KDF (bcrypt/scrypt/argon2/pbkdf2>=600k) for passwords.
- Keys come from a KMS/Vault/env-injected secret, never hardcoded; separate keys per purpose; include a MAC.
