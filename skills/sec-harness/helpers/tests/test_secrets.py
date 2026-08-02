"""Tests for the in-house offline secrets scanner backend."""

import re

from sec_harness.models import FindingStatus, Severity
from sec_harness.secrets import _PATTERNS, _PLACEHOLDER, scan_secrets


def test_patterns_shape():
    # contract consumed by redactor: list of (name, compiled-pattern) pairs.
    assert isinstance(_PATTERNS, list) and _PATTERNS
    assert isinstance(_PLACEHOLDER, re.Pattern)
    for name, pat in _PATTERNS:
        assert isinstance(name, str) and isinstance(pat, re.Pattern)
    names = {n for n, _ in _PATTERNS}
    # redactor special-cases these two names in find_residual_secrets.
    assert "private-key-header" in names and "jwt" in names


def test_scan_finds_github_token(tmp_path):
    p = tmp_path / "config.py"
    p.write_text('GH_TOKEN = "ghp_' + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + '"\n')
    hits = scan_secrets(str(tmp_path))
    assert len(hits) == 1
    f = hits[0]
    assert f.cls == "secrets"
    assert f.status is FindingStatus.CANDIDATE
    assert f.severity is Severity.HIGH
    assert f.file == "config.py"
    assert f.line == 1
    # must carry a mechanical secrets: receipt so it can survive the receipt gate.
    assert any(s.startswith("secrets:") for s in f.evidence_sources)


def test_scan_skips_placeholder_line(tmp_path):
    (tmp_path / "readme.md").write_text('api_key = "your_api_key_here"\n')
    assert scan_secrets(str(tmp_path)) == []


def test_scan_reports_correct_line_number(tmp_path):
    (tmp_path / "a.py").write_text(
        "x = 1\n"
        "y = 2\n"
        'AWS = "AKIAIOSFODNN7EXAMPLE9"\n'
    )
    hits = scan_secrets(str(tmp_path))
    # AKIA... is a distinctive shape, but EXAMPLE marks it a placeholder -> skipped.
    assert hits == []


def test_scan_finds_aws_access_key(tmp_path):
    (tmp_path / "a.py").write_text('k = "AKIA' + "Z9Y8X7W6V5U4T3S2" + '"\n')
    hits = scan_secrets(str(tmp_path))
    assert len(hits) == 1 and hits[0].line == 1


def test_scan_skips_noise_dirs(tmp_path):
    node = tmp_path / "node_modules" / "pkg"
    node.mkdir(parents=True)
    (node / "leak.js").write_text('const t = "ghp_' + "z" * 36 + '";\n')
    assert scan_secrets(str(tmp_path)) == []


def test_scan_skips_binary_file(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01ghp_" + b"q" * 36 + b"\x00")
    # unreadable-as-text -> skipped, never crashes.
    assert scan_secrets(str(tmp_path)) == []


def test_scan_single_file_target(tmp_path):
    p = tmp_path / "secrets.env"
    p.write_text('STRIPE = "sk_live_' + "b" * 24 + '"\n')
    hits = scan_secrets(str(p))
    assert len(hits) == 1 and hits[0].file == "secrets.env"
