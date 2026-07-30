"""Emit findings as a minimal, valid SARIF 2.1.0 document."""

from __future__ import annotations

from sec_harness.models import Finding, Severity

_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _level(sev: Severity) -> str:
    """Map a normalized severity to a SARIF result level.

    Args:
        sev: Severity enum value.

    Returns:
        A SARIF level string: "error", "warning", or "note".
    """
    if sev in (Severity.HIGH, Severity.CRITICAL):
        return "error"
    if sev is Severity.MEDIUM:
        return "warning"
    return "note"


def to_sarif(findings: list[Finding], tool_name: str = "sec-harness") -> dict:
    """Convert findings to a SARIF 2.1.0 document.

    Args:
        findings: Findings to serialize.
        tool_name: Name recorded as the SARIF tool driver.

    Returns:
        A SARIF 2.1.0 document as a dict.
    """
    results = [
        {
            "ruleId": f.rule_id,
            "level": _level(f.severity),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        for f in findings
    ]
    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [{"tool": {"driver": {"name": tool_name, "rules": []}}, "results": results}],
    }
