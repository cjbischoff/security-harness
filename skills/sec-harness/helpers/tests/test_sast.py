"""Tests for semgrep parsing + running."""

from sec_harness.evidence import is_tool_receipt
from sec_harness.models import FindingStatus, Severity
from sec_harness.sast import parse_semgrep_json, run_semgrep

SAMPLE = {
    "results": [
        {
            "check_id": "rules.python-sqli-string-format",
            "path": "fixtures/vulnerable_repo/app.py",
            "start": {"line": 18},
            "extra": {
                "message": "SQL injection",
                "severity": "ERROR",
                "metadata": {"cls": "sqli"},
                "lines": "cur.execute(...)",
            },
        }
    ]
}


def test_parse_maps_fields():
    findings = parse_semgrep_json(SAMPLE)
    assert len(findings) == 1
    f = findings[0]
    assert f.cls == "sqli"
    assert f.severity is Severity.HIGH
    assert f.status is FindingStatus.CANDIDATE
    assert f.file == "fixtures/vulnerable_repo/app.py"
    assert f.line == 18
    assert f.rule_id == "rules.python-sqli-string-format"


def test_parse_defaults_cls_when_missing():
    payload = {"results": [{"check_id": "r", "path": "a.py", "start": {"line": 1}, "extra": {"severity": "WARNING", "message": "m", "metadata": {}}}]}
    f = parse_semgrep_json(payload)[0]
    assert f.cls == "unknown"
    assert f.severity is Severity.MEDIUM


def test_run_semgrep_invokes_binary_and_parses(monkeypatch):
    import json

    class FakeCompleted:
        stdout = json.dumps(SAMPLE)
        returncode = 0

    def fake_run(cmd, capture_output, text, check):
        assert cmd[0] == "semgrep"
        assert "--json" in cmd
        return FakeCompleted()

    findings = run_semgrep("target", "rules/smoke.yaml", runner=fake_run)
    assert findings[0].cls == "sqli"


def test_parse_semgrep_uses_cwe_when_no_cls():
    """Derive cls from CWE field when cls is not present."""
    payload = {
        "results": [
            {
                "check_id": "go.lang.security.audit.crypto.use-of-md5",
                "path": "x.go",
                "start": {"line": 3},
                "extra": {
                    "severity": "WARNING",
                    "message": "md5",
                    "metadata": {"cwe": ["CWE-327: Use of a Broken Crypto Algorithm"]},
                },
            }
        ]
    }
    f = parse_semgrep_json(payload)[0]
    assert f.cls == "crypto"  # derived from cwe, not "unknown"


def test_parse_semgrep_stamps_tool_receipt():
    """Evidence sources must include semgrep tool receipt at parse time."""
    findings = parse_semgrep_json(SAMPLE)
    f = findings[0]
    # receipt keys on the full check_id (matches codeql granularity; avoids collisions)
    assert f.evidence_sources == ["semgrep:rules.python-sqli-string-format"]
    # Verify it is recognized as a genuine tool receipt
    assert is_tool_receipt(f.evidence_sources[0]) is True
