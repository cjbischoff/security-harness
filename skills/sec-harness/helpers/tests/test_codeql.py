"""Tests for CodeQL SARIF parsing + class mapping."""

import json
from pathlib import Path

from sec_harness.codeql import cls_from_tags, parse_codeql_sarif
from sec_harness.evidence import is_tool_receipt
from sec_harness.models import FindingStatus, Severity

SARIF = json.loads((Path(__file__).parent / "fixtures" / "sample_codeql.sarif").read_text())


def test_cls_from_cwe_tags():
    assert cls_from_tags("go/sql-injection", ["external/cwe/cwe-089"]) == "sqli"
    assert cls_from_tags("go/ssrf", ["external/cwe/cwe-918"]) == "ssrf"
    assert cls_from_tags("go/whatever", ["security"]) == "unknown"


def test_parse_codeql_sarif_maps_results():
    findings = parse_codeql_sarif(SARIF)
    assert len(findings) == 2
    by_cls = {f.cls: f for f in findings}
    assert by_cls["sqli"].file == "internal/db/q.go"
    assert by_cls["sqli"].line == 42
    assert by_cls["sqli"].status is FindingStatus.CANDIDATE
    assert by_cls["sqli"].severity is Severity.HIGH  # security-severity 8.8 -> high
    assert by_cls["ssrf"].severity is Severity.CRITICAL  # 9.1 -> critical


def test_run_codeql_invokes_cli_and_parses(tmp_path):
    from sec_harness.codeql import run_codeql

    db_dir = tmp_path / "db"
    sarif_out = tmp_path / "codeql.sarif"
    calls = []

    def fake_runner(cmd, capture_output, text, check):
        calls.append(cmd)
        if cmd[:3] == ["codeql", "database", "analyze"]:
            sarif_out.write_text(json.dumps(SARIF))
        class R:
            returncode = 0
            stdout = ""
        return R()

    findings = run_codeql("src", "go", str(db_dir), runner=fake_runner)
    assert calls[0][:3] == ["codeql", "database", "create"]
    assert "--language=go" in calls[0]
    assert calls[1][:3] == ["codeql", "database", "analyze"]
    assert any("security-extended" in a for a in calls[1])
    assert len(findings) == 2  # parsed from the SARIF the fake runner wrote


def test_run_codeql_raises_on_create_failure(tmp_path):
    import pytest

    from sec_harness.codeql import CodeQLError, run_codeql

    class R:
        returncode = 32
        stdout = ""
        stderr = "build failed: go module resolution error"

    with pytest.raises(CodeQLError, match="create failed"):
        run_codeql("src", "go", str(tmp_path / "db"), runner=lambda *a, **k: R())


def test_run_codeql_raises_when_no_sarif(tmp_path):
    import pytest

    from sec_harness.codeql import CodeQLError, run_codeql

    class R:  # both create + analyze "succeed" but no SARIF is written
        returncode = 0
        stdout = ""
        stderr = ""

    with pytest.raises(CodeQLError, match="no SARIF"):
        run_codeql("src", "go", str(tmp_path / "db"), runner=lambda *a, **k: R())


def test_cls_from_tags_delegates_and_covers_new_cwes():
    assert cls_from_tags("go/sql-injection", ["external/cwe/cwe-089"]) == "sqli"   # unchanged
    assert cls_from_tags("go/log-injection", ["external/cwe/cwe-117"]) == "log-injection"  # newly covered


def test_parse_codeql_resolves_uribaseid():
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": "go/x", "properties": {"tags": ["external/cwe/cwe-089"], "security-severity": "8.0"}}]}},
        "originalUriBaseIds": {"SRCROOT": {"uri": "file:///repo/"}},
        "results": [{"ruleId": "go/x", "message": {"text": "m"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "cmd/app/main.go", "uriBaseId": "SRCROOT"},
                         "region": {"startLine": 42}}}]}]}]}
    f = parse_codeql_sarif(sarif)[0]
    assert f.file == "repo/cmd/app/main.go"     # base 'repo' prefixed, scheme/leading-slash stripped
    assert f.line == 42


def test_parse_codeql_stamps_tool_receipt():
    """Evidence sources must include codeql tool receipt at parse time."""
    findings = parse_codeql_sarif(SARIF)
    assert len(findings) == 2
    for f in findings:
        # Each finding must have codeql:<rule_id> evidence source
        assert any(src.startswith("codeql:") for src in f.evidence_sources), \
            f"finding {f.id} missing codeql: evidence source"
        # Verify all codeql sources are recognized as genuine tool receipts
        for src in f.evidence_sources:
            if src.startswith("codeql:"):
                assert is_tool_receipt(src) is True


def test_cls_from_tags_falls_back_to_rule_id():
    from sec_harness.codeql import cls_from_tags
    # no CWE tag -> rule-id router rescues it instead of "unknown"
    assert cls_from_tags("js/user-controlled-bypass", []) == "authn"
    assert cls_from_tags("js/insecure-randomness", ["some/other/tag"]) == "crypto"
    # CWE tag still wins when present
    assert cls_from_tags("js/whatever", ["external/cwe/cwe-089"]) == "sqli"
    # neither maps -> unknown
    assert cls_from_tags("js/regex/missing-regexp-anchor", []) == "unknown"
