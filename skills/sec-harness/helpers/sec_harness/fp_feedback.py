"""Cross-session false-positive feedback: prior rejects as negative few-shot.

Rejected findings persist in the workspace across passes. Feeding them back into the
next scan's discovery/critic prompts steers the model away from previously-refuted
patterns. The block is repo-derived untrusted text and is envelope-wrapped: it is
evidence about past rejections, never instructions.
"""

from __future__ import annotations

from sec_harness.envelope import wrap_untrusted
from sec_harness.models import FindingStatus
from sec_harness.workspace import Workspace, read_findings


def _reason(finding) -> str:
    """Return the recorded rejection reason (last history reason) or the message."""
    for event in reversed(finding.history):
        if event.get("reason"):
            return str(event["reason"])
    return finding.message


def render_fp_feedback(ws: Workspace, *, cap: int = 50) -> str:
    """Render prior rejected findings as an envelope-wrapped negative-example block.

    Args:
        ws: Workspace to read prior findings from.
        cap: Maximum examples to include (first ``cap`` unique findings in ascending id order).

    Returns:
        An ``<untrusted>``-wrapped block, or ``""`` when there are no rejected findings.
    """
    rejected = [f for f in read_findings(ws) if f.status is FindingStatus.REJECTED]
    if not rejected:
        return ""
    seen: set[str] = set()
    lines: list[str] = []
    for f in sorted(rejected, key=lambda f: f.id):
        key = f.fingerprint or f"{f.cls}:{f.file}:{f.line}"
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- class={f.cls} at {f.file}:{f.line} — REJECTED: {_reason(f)}")
        if len(lines) >= cap:
            break
    body = "These candidates were investigated and REJECTED in a prior pass. Do not "
    body += "re-raise them unless code changed materially:\n" + "\n".join(lines)
    return wrap_untrusted(body, kind="prior-rejections")
