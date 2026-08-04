"""Machine-checked crypto policy (F13).

Deterministic trust-chain gate for the crypto class: is the algorithm approved, are
parameters above the floor, and does the key come from an approved source? Reads two
YAML-ish policy files (parsed without a YAML dependency — simple key/list/scalar).
"""

from __future__ import annotations

import re
from pathlib import Path

_DENIED_ALGOS = {"md5", "sha1", "des", "3des", "rc4", "ecb", "mcrypt", "rijndael-ctr-nomac"}
# param floors — pbkdf2 per OWASP Password Storage Cheat Sheet (PBKDF2-HMAC-SHA256: 600,000
# iterations, checked 2026-08-04; supersedes the older ~100,000-iteration guidance)
_FLOORS = {"rsa": 3072, "pbkdf2": 600000, "ecc": 256, "aes": 128}
_APPROVED_KEY_SOURCES = {"kms", "vault", "chamber", "gcp-secret-manager", "azure-keyvault", "env"}
_DENIED_KEY_SOURCES = {"literal", "hardcoded", "filesystem", "source"}
_NON_AEAD_MODES = ("cbc", "cfb", "ofb")
_AEAD_INDICATORS = ("gcm", "ccm", "poly1305", "hmac")
_BARE_FAST_HASHES = ("sha256", "sha512", "md5", "sha1")
_KDF_INDICATORS = ("pbkdf2", "bcrypt", "scrypt", "argon2")


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9-]", "", (s or "").lower())


def check(algo: str, params: dict | None = None, key_source: str = "") -> dict:
    """Check an algorithm + params + key source against policy.

    Args:
        algo: Algorithm name (e.g. ``aes-256-gcm``, ``md5``, ``rsa``).
        params: Optional ``{rsa: 2048, pbkdf2: 50000, ecc: 224, ...}`` sizes.
        key_source: Where the key comes from (``kms``/``env``/``literal``/...).

    Returns:
        ``{ok: bool, violations: [str]}``.
    """
    params = params or {}
    a = _norm(algo)
    violations: list[str] = []
    if any(d in a for d in _DENIED_ALGOS):
        violations.append(f"denied algorithm: {algo}")
    for fam, floor in _FLOORS.items():
        if fam in a or fam in params:
            size = params.get(fam)
            if size is not None and int(size) < floor:
                violations.append(f"{fam} size {size} below floor {floor}")
    if any(m in a for m in _NON_AEAD_MODES) and not any(i in a for i in _AEAD_INDICATORS):
        violations.append(f"non-AEAD block cipher mode without MAC: {algo}")
    if params.get("kdf_context") and any(h in a for h in _BARE_FAST_HASHES) and not any(
        k in a for k in _KDF_INDICATORS
    ):
        violations.append(f"bare fast hash used as KDF: {algo}")
    if key_source:
        ks = _norm(key_source)
        if ks in _DENIED_KEY_SOURCES:
            violations.append(f"denied key source: {key_source}")
        elif ks not in _APPROVED_KEY_SOURCES:
            violations.append(f"unrecognized key source (not approved): {key_source}")
    return {"ok": not violations, "violations": violations}


def load_policy(path: str | Path) -> dict:
    """Load a simple policy YAML (approved:/denied: lists). Best-effort, no PyYAML."""
    out: dict[str, list[str]] = {}
    cur = None
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if not line.startswith((" ", "-")) and line.rstrip().endswith(":"):
            cur = line.strip().rstrip(":")
            out[cur] = []
        elif line.strip().startswith("-") and cur:
            out[cur].append(line.strip()[1:].strip())
    return out
