"""Tests for the pre-send secrets redactor."""
import pytest

from sec_harness.redactor import (
    SecretsPresent,
    find_residual_secrets,
    redact,
    safe_for_prompt,
    verify_no_secrets,
)


def test_redact_masks_distinctive_token():
    src = 'gh = "ghp_' + "a" * 36 + '"\n'
    red = redact(src)
    assert "ghp_" not in red and "REDACTED" in red


def test_redact_generic_assignment_keeps_key():
    red = redact('password = "hunter2secret"')
    assert "hunter2secret" not in red and "password" in red and "REDACTED" in red


def test_verify_aborts_on_residual_private_key():
    with pytest.raises(SecretsPresent):
        verify_no_secrets("-----BEGIN RSA PRIVATE KEY-----\nabc\n")


def test_safe_for_prompt_redacts_then_passes():
    out = safe_for_prompt('token = "sk_live_' + "b" * 24 + '"')
    assert "sk_live_" not in out
    verify_no_secrets(out)  # no raise


def test_placeholder_not_flagged():
    assert find_residual_secrets('key = "your_api_key_here example"') == []


def test_findings_guided_masking(tmp_path):
    # a secrets finding on line 2 whose value shape our patterns miss -> RHS masked
    from sec_harness.models import Finding, FindingStatus, Severity
    f = Finding(id="S1", rule_id="secrets:x", cls="secrets", status=FindingStatus.CANDIDATE,
                severity=Severity.HIGH, file="c.py", line=2, message="m")
    red = redact("a = 1\nweird_secret = supersecretvalue\n", findings=[f])
    assert "supersecretvalue" not in red
