"""Fix completeness disposition (F11).

Grades a fix ``completeness_tier`` conservative-first — NEVER silently FULL — and
enforces cross-field honesty so a report can't claim more than the evidence supports.
FULL requires three cumulative signals; ambiguity routes to human review, never to a
silent FULL.
"""

from __future__ import annotations

TIERS = ("FULL", "MITIGATION", "WORKAROUND")
STATUSES = (
    "VERIFIED_FULL", "VERIFIED_MITIGATION", "VERIFIED_WORKAROUND",
    "ALREADY_FIXED", "CANNOT_AUTO_FIX", "NEEDS_MANUAL_REVIEW",
    "BREAKING_CHANGE", "FAILED",
)


def compute_tier(signals: dict) -> str:
    """Conservative-first tier from fix signals; ``"LLM_REVIEW"`` when ambiguous.

    Args:
        signals: ``{sink_signature_changed: bool, callers_routed: bool,
            test_discriminates: bool}``. ``callers_routed`` must mean "callers
            re-checked AND the routed set is non-empty".

    Returns:
        ``FULL`` iff all three signals hold; ``MITIGATION`` iff the sink changed OR
        callers were routed (partial); ``WORKAROUND`` iff only a discriminating test
        exists; ``"LLM_REVIEW"`` iff no signal at all (caller escalates, then falls to
        NEEDS_MANUAL_REVIEW — never a silent FULL).
    """
    sink = bool(signals.get("sink_signature_changed"))
    routed = bool(signals.get("callers_routed"))
    test = bool(signals.get("test_discriminates"))
    if sink and routed and test:
        return "FULL"
    if sink or routed:
        return "MITIGATION"
    if test:
        return "WORKAROUND"
    return "LLM_REVIEW"


def validate(disposition: dict) -> list[str]:
    """Enforce cross-field honesty constraints; return errors (empty if honest).

    Constraints (mirror the JSON schema + render layer):
    - tier ∈ TIERS; status ∈ STATUSES.
    - FULL ⇒ residual_vectors empty; non-FULL ⇒ residual_vectors non-empty.
    - FULL + a VERIFIED status ⇒ discrimination_evidence with pre==fail, post==pass.
    - sweep_revised true ⇒ NOT FULL (a revised sweep means the fix wasn't complete).
    """
    errs: list[str] = []
    tier = disposition.get("completeness_tier")
    status = disposition.get("status")
    residual = disposition.get("residual_vectors", [])
    if tier not in TIERS:
        errs.append(f"bad completeness_tier {tier!r}")
    if status is not None and status not in STATUSES:
        errs.append(f"bad status {status!r}")
    if tier == "FULL" and residual:
        errs.append("FULL fix must have empty residual_vectors")
    if tier in ("MITIGATION", "WORKAROUND") and not residual:
        errs.append(f"{tier} fix must document residual_vectors")
    if tier == "FULL" and status and status.startswith("VERIFIED"):
        de = disposition.get("discrimination_evidence") or {}
        if not (de.get("pre") == "fail" and de.get("post") == "pass"):
            errs.append("FULL+VERIFIED requires discrimination_evidence pre=fail/post=pass")
    if disposition.get("sweep_revised") and tier == "FULL":
        errs.append("sweep_revised=true is inconsistent with FULL")
    return errs
