# CWE-class extension — crypto

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Authenticated encryption (AES-GCM / libsodium) or a slow KDF for passwords; keys from a
managed source (KMS/Vault/env), never literal.

## Mechanical policy gate
Run `sec_harness.crypto_policy.check(algo, params, key_source)` against
`references/approved-crypto-algorithms.yaml` + `approved-key-sources.yaml`. A denied algo
(md5/sha1/des/ecb/mcrypt), a param below floor (rsa<3072, pbkdf2<600000, ecc<256), or a
denied key source (literal/hardcoded/filesystem) is a violation — cite it in the finding.

## FP traps
md5/sha1 used as a non-security checksum/cache-key/dedup id is NOT a finding (verify the
use). A weak algo behind an approved outer layer may be defense-in-depth, not exploitable.

## Class boundary
**IS:** a weak primitive, insufficient parameter, or bad key source protecting a
genuinely sensitive value (per the mechanical policy gate above).
**IS NOT:**
- The authentication FLOW being bypassable (missing check, forged token accepted) with
  the underlying primitive itself sound → `cls: authn`. Crypto is the primitive; authn is
  whether the flow actually calls it correctly.
- A missing/incorrect HMAC signature check on a webhook payload → `cls:
  webhook-verification` if that key is in scope for this repo; otherwise keep as crypto
  but name the specific check missing (constant-time compare vs raw `==`) rather than a
  generic "weak crypto" label.

## Proof tuple (required evidence)

A confirmable crypto weakness needs all three, each with a `file:line`:
1. **Sensitive use** — the value protected is a secret, token, password, or signature (not a checksum/cache-key/dedup id).
2. **Weak primitive or key source** — a denied algo, sub-floor param, or denied key source per the mechanical policy gate above (defer the pass/fail call to `crypto_policy.check`).
3. **Attacker benefit** — the weakness is exploitable by an attacker in this context (forgeable signature, recoverable plaintext, brute-forceable key).

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
