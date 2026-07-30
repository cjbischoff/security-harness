"""Independent fact-checker application (F8).

A late phase (after adversarial-validate) spawns a fresh agent per confirmed finding to
re-verify the WRITTEN finding's citations/scope/severity against source — catching
citation drift and confidence inflation that tool receipts don't. This module validates
the agent's verdict JSON and applies it deterministically.
"""

from __future__ import annotations

from sec_harness.models import Finding, FindingStatus

VERDICTS = ("VERIFIED", "CORRECTED", "REJECTED")
# fields a CORRECTED verdict may fix in place
_CORRECTABLE = {"file", "line", "severity", "cvss_vector", "message"}


def validate_verdict(d: dict) -> list[str]:
    """Return errors for a fact-check verdict dict (empty if valid)."""
    errs = []
    if d.get("verdict") not in VERDICTS:
        errs.append(f"bad verdict {d.get('verdict')!r}")
    if d.get("verdict") == "CORRECTED":
        if d.get("field") not in _CORRECTABLE:
            errs.append(f"CORRECTED requires field in {sorted(_CORRECTABLE)}")
        if "value" not in d:
            errs.append("CORRECTED requires a value")
    return errs


def apply_verdict(f: Finding, d: dict) -> Finding:
    """Apply a validated fact-check verdict to a finding in place.

    - VERIFIED: stamp ``verification = "fact-checked"``.
    - CORRECTED: fix the cited field, then stamp fact-checked.
    - REJECTED: demote to ``rejected``.

    Args:
        f: The finding.
        d: The verdict dict ``{verdict, field?, value?, reasoning?}``.

    Returns:
        The mutated finding.

    Raises:
        ValueError: if the verdict is invalid.
    """
    errs = validate_verdict(d)
    if errs:
        raise ValueError("; ".join(errs))
    verdict = d["verdict"]
    if verdict == "REJECTED":
        f.status = FindingStatus.REJECTED
        f.history.append({"event": "factcheck:rejected", "reason": d.get("reasoning", "")})
        return f
    if verdict == "CORRECTED":
        field, value = d["field"], d["value"]
        if field == "severity":
            from sec_harness.models import Severity
            f.severity = Severity(value)
        elif field == "line":
            f.line = int(value)
        else:
            setattr(f, field, value)
        f.history.append({"event": "factcheck:corrected", "field": field, "value": value})
    f.verification = "fact-checked"
    f.history.append({"event": "factcheck:verified"})
    return f
