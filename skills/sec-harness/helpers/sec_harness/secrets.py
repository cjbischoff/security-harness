"""In-house offline secrets scanner: distinctive-token patterns + a file walker.

Two roles. As a data module it exposes ``_PATTERNS`` (named high-confidence
secret-token regexes) and ``_PLACEHOLDER`` (a marker that suppresses obvious
non-secrets like ``your_api_key_here``); the pre-send ``redactor`` imports both
to mask and verify. As a backend it exposes ``scan_secrets`` — a dependency-free
walk that emits one ``Finding`` per line carrying a hardcoded secret, each with a
``secrets:<name>`` mechanical receipt so it can pass the confidence gate.

The patterns are deliberately distinctive (provider-prefixed tokens, key
headers) rather than generic ``password = "..."`` shapes: generic assignments are
handled more aggressively by the redactor's own safety-net, but they are too
noisy to raise as findings here. Detection favors precision; the redactor favors
recall.
"""

from __future__ import annotations

import re
from pathlib import Path

from sec_harness.models import Finding, FindingStatus, Severity

# Distinctive, high-confidence secret shapes. NAMES ARE PART OF THE CONTRACT:
# redactor.find_residual_secrets special-cases "private-key-header" and "jwt"
# (they are flagged even inside an already-masked line).
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("private-key-header", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
]

# Suppresses obvious non-secrets (docs, templates, samples). Used both to skip a
# line during scanning and — in the redactor — to avoid aborting on a placeholder.
_PLACEHOLDER: re.Pattern = re.compile(
    r"(?ix)("
    r"your[_-]?"          # your_api_key
    r"|[_-]?here\b"       # api_key_here
    r"|\bexample\b"       # AKIA...EXAMPLE
    r"|\bplaceholder\b"
    r"|change[_-]?me"
    r"|\bredacted\b"      # the redaction mask itself
    r"|\bdummy\b"
    r"|\bsample\b"
    r"|<[a-z0-9_ .-]+>"   # <your-token>
    r"|x{4,}"             # xxxxxxxx
    r"|\.\.\."
    r")"
)

_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".sec-harness", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "vendor", ".idea", ".vscode",
}
_MAX_BYTES = 1_000_000  # skip files larger than 1 MB — secrets live in config, not blobs


def _is_skippable(path: Path, root: Path) -> bool:
    """Return True for a path under a noise directory or too large to be config text."""
    parts = path.relative_to(root).parts if path != root else ()
    if any(part in _SKIP_DIRS for part in parts):
        return True
    try:
        return path.stat().st_size > _MAX_BYTES
    except OSError:
        return True


def scan_secrets(target: str) -> list[Finding]:
    """Scan a file or directory for hardcoded secrets.

    Walks ``target`` (a single file or a directory tree), matching each line
    against ``_PATTERNS``. Lines carrying a placeholder marker are skipped, as
    are binary/unreadable files and known noise directories. At most one finding
    is emitted per line (the first matching pattern wins).

    Args:
        target: Path to a file or directory to scan.

    Returns:
        A list of candidate ``Finding`` objects (``cls="secrets"``), each with a
        ``secrets:<name>`` mechanical evidence receipt. Empty if nothing matched.
    """
    root = Path(target)
    if root.is_file():
        paths = [root]
        rel_base = root.parent
    else:
        paths = sorted(p for p in root.rglob("*") if p.is_file())
        rel_base = root

    findings: list[Finding] = []
    idx = 0
    for path in paths:
        if root.is_dir() and _is_skippable(path, root):
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue  # NUL byte — binary file (valid UTF-8 but not source text)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue  # binary or unreadable — skip, never crash the scan
        rel = str(path.relative_to(rel_base)) if root.is_dir() else path.name
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _PLACEHOLDER.search(line):
                continue
            for name, pat in _PATTERNS:
                if pat.search(line):
                    idx += 1
                    findings.append(Finding(
                        id=f"C-{idx:04d}",
                        rule_id=f"secrets:{name}",
                        cls="secrets",
                        status=FindingStatus.CANDIDATE,
                        severity=Severity.HIGH,
                        file=rel,
                        line=lineno,
                        message=f"hardcoded secret ({name})",
                        evidence_sources=[f"secrets:{name}"],
                    ))
                    break  # one finding per line
    return findings
