# CWE-class extension — crypto

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Authenticated encryption (AES-GCM / libsodium) or a slow KDF for passwords; keys from a
managed source (KMS/Vault/env), never literal.

## Mechanical policy gate
Run `sec_harness.crypto_policy.check(algo, params, key_source)` against
`references/approved-crypto-algorithms.yaml` + `approved-key-sources.yaml`. A denied algo
(md5/sha1/des/ecb/mcrypt), a param below floor (rsa<3072, pbkdf2<100000, ecc<256), or a
denied key source (literal/hardcoded/filesystem) is a violation — cite it in the finding.

## FP traps
md5/sha1 used as a non-security checksum/cache-key/dedup id is NOT a finding (verify the
use). A weak algo behind an approved outer layer may be defense-in-depth, not exploitable.
