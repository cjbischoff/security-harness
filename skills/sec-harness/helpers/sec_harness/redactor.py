"""Redact secret VALUES from code before it enters any LLM prompt, then verify.

Three-step control (Cisco pattern): (1) mask secret values located by our secrets
scan and/or a regex safety-net; (2) hard-verify no high-confidence secret remains;
(3) abort the caller if it does. Redaction masks the matched span (not the whole
line) so the code stays reviewable. Never sends a secret to a model even if an
earlier phase missed it.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from sec_harness.secrets import _PATTERNS, _PLACEHOLDER

_MASK = "***REDACTED***"

# Redaction may be MORE aggressive than detection (masking is harmless), so it adds
# generic assignment patterns on top of the distinctive-token patterns. Verification
# uses only the distinctive set (avoid over-aborting on benign generic assignments).
_REDACT_EXTRA: list[tuple[str, re.Pattern]] = [
    ("generic-assignment", re.compile(
        r"""(?ix)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?key)\b\s*[:=]\s*['"]([^'"]{6,})['"]""")),
    ("basic-auth-url", re.compile(r"://[^:/@\s]+:([^@/\s]{4,})@")),
]


class SecretsPresent(RuntimeError):
    """Raised when a high-confidence secret survives redaction (call must abort)."""


def redact(text: str, findings=None) -> str:
    """Mask secret values in ``text``.

    Args:
        text: Source text about to be embedded in a prompt.
        findings: Optional secrets findings (from ``secrets.scan_secrets``) whose
            ``line`` numbers pinpoint values to mask (belt); the regex safety-net
            (suspenders) runs regardless.

    Returns:
        ``text`` with secret spans replaced by ``***REDACTED***``.
    """
    lines = text.splitlines(keepends=False)
    target_lines = {f.line for f in (findings or [])}
    out = []
    for i, line in enumerate(lines, start=1):
        red = line
        for _name, pat in _PATTERNS:
            red = pat.sub(_MASK, red)
        for _name, pat in _REDACT_EXTRA:
            # mask only the captured secret group, keep the key/context readable
            red = pat.sub(lambda m: m.group(0).replace(m.group(1), _MASK), red)
        if i in target_lines and red == line and "=" in line:
            # a secrets-finding said this line is dirty but no pattern matched the
            # value shape — mask the RHS of the last assignment conservatively.
            red = re.sub(r"([:=]\s*).+$", r"\1" + _MASK, line, count=1)
        out.append(red)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def find_residual_secrets(text: str) -> list[str]:
    """Return names of high-confidence secret patterns still present (placeholders excluded)."""
    residual = []
    for line in text.splitlines():
        if _PLACEHOLDER.search(line):
            continue
        for name, pat in _PATTERNS:
            if name in ("private-key-header", "jwt"):
                if pat.search(line):
                    residual.append(name)
            elif pat.search(line) and _MASK not in line:
                residual.append(name)
    return residual


def verify_no_secrets(text: str) -> None:
    """Raise :class:`SecretsPresent` if a high-confidence secret survives.

    Args:
        text: Redacted text about to be sent to a model.

    Raises:
        SecretsPresent: if any distinctive secret pattern still matches.
    """
    residual = find_residual_secrets(text)
    if residual:
        raise SecretsPresent(f"secret(s) survived redaction: {sorted(set(residual))}")


def safe_for_prompt(text: str, findings=None) -> str:
    """Redact then verify: the single call to make code safe to embed in a prompt.

    Args:
        text: Source text.
        findings: Optional secrets findings to guide masking.

    Returns:
        Redacted text, guaranteed free of high-confidence secrets.

    Raises:
        SecretsPresent: if a secret cannot be removed (the caller must NOT send it).
    """
    red = redact(text, findings)
    verify_no_secrets(red)
    return red


def main(argv: list[str] | None = None) -> int:
    """CLI: check a file/dir for residual secrets after redaction (preflight)."""
    p = argparse.ArgumentParser(prog="sec-harness-redactor")
    p.add_argument("path")
    args = p.parse_args(argv)
    root = Path(args.path)
    files = [root] if root.is_file() else [q for q in root.rglob("*") if q.is_file()]
    dirty = 0
    for q in files:
        try:
            residual = find_residual_secrets(q.read_text(errors="ignore"))
        except OSError:
            continue
        if residual:
            dirty += 1
            print(f"{q}: {sorted(set(residual))}")
    print(f"{dirty} file(s) with residual secrets")
    return 1 if dirty else 0


if __name__ == "__main__":
    raise SystemExit(main())
