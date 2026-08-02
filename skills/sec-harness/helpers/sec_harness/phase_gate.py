"""Reusable phase adversary gate — the deterministic half (principle: adversarial-review all things).

sec-harness already battle-tests investigate findings (critic + adversarial-validate). Every
EARLIER phase — recon, architecture, threat-model, C1 context — emits analysis/context that
later phases trust. This module runs the deterministic pre-check for those phases: a claim
whose cited code reference does not resolve (or whose schema is malformed) is rejected with no
agent spawned; everything else is marked ``to-adversary`` for an independent opus review. It
also assembles a per-gate audit record written to ``kb/gates/<phase>.json``.

The finding phases keep their existing per-finding gate (the FP ladder); this is for the
analysis/context phases that had none.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


def ref_resolves(root: str | Path, ref: str) -> bool:
    """True if ``ref`` points at real code under ``root``.

    Accepts a bare path (file or directory must exist) or a ``file:line`` reference (the file
    must exist and the line be in range). This is what code can verify about an LLM's claim; it
    never judges whether the analysis is *correct* — that is the adversary's job.

    Args:
        root: Target repo root.
        ref: A repo-relative path, optionally suffixed ``:line``.

    Returns:
        True if the reference resolves to a real file/dir (and in-range line).
    """
    ref = (ref or "").strip()
    if not ref:
        return False
    path, line = ref, None
    if ":" in ref:
        head, tail = ref.rsplit(":", 1)
        if tail.isdigit():
            path, line = head, int(tail)
    fp = Path(root) / path
    if line is None:
        return fp.exists()
    if not fp.is_file():
        return False
    try:
        n = len(fp.read_text(errors="replace").splitlines())
    except OSError:
        return False
    return 1 <= line <= n


@dataclass
class GateDecision:
    """Deterministic verdict for one claim before any adversary runs."""

    claim_id: str
    status: str  # "reject" | "to-adversary"
    reasons: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    text: str = ""


def run_phase_checks(claims: list[dict], target_root: str | Path) -> list[GateDecision]:
    """Return a :class:`GateDecision` per claim for an analysis/context phase.

    Args:
        claims: Each is ``{"id": str, "text": str, "refs": [path or file:line, ...]}`` — the
            claim's assertion and the code references it rests on.
        target_root: The scanned repo root the references resolve against.

    Returns:
        One decision per claim, in input order. ``reject`` = a hard structural failure (a cited
        reference does not resolve); ``to-adversary`` = well-formed, worth an adversary's time.
        A claim with no refs is sent to the adversary on judgment alone (logged).
    """
    out: list[GateDecision] = []
    for i, claim in enumerate(claims):
        cid = str(claim.get("id", i))
        reasons: list[str] = []
        reject = False
        refs = claim.get("refs", [])
        for ref in refs:
            if not ref_resolves(target_root, ref):
                reasons.append(f"ref does not resolve: {ref!r}")
                reject = True
        if not refs:
            reasons.append("no code refs to verify — sent to adversary on judgment alone")
        out.append(GateDecision(cid, "reject" if reject else "to-adversary", reasons,
                                 refs=list(refs), text=str(claim.get("text", ""))))
    return out


def build_gate_record(
    phase: str,
    decisions: list[GateDecision],
    verdicts: dict[str, str] | None = None,
) -> dict:
    """Assemble a JSON-serializable audit record for one phase gate.

    Args:
        phase: Phase name.
        decisions: Output of :func:`run_phase_checks`.
        verdicts: Optional ``claim_id`` → adversary verdict
            (``CONFIRMED`` / ``WEAKENED`` / ``INVALIDATED``) filled in after the agent runs.

    Returns:
        ``{phase, claims_in, rejected_deterministically, sent_to_adversary, survivors,
        decisions, verdicts, claims}``, where ``claims`` maps each sent-to-adversary
        claim id to its ``{text, refs}`` so the adversary reviews content, not opaque ids.
    """
    verdicts = verdicts or {}
    rejected_det = [d.claim_id for d in decisions if d.status == "reject"]
    to_adv = [d.claim_id for d in decisions if d.status == "to-adversary"]
    survivors = [c for c in to_adv if verdicts.get(c, "CONFIRMED") != "INVALIDATED"]
    claims = {d.claim_id: {"text": d.text, "refs": d.refs}
              for d in decisions if d.status == "to-adversary"}
    return {
        "phase": phase,
        "claims_in": len(decisions),
        "rejected_deterministically": rejected_det,
        "sent_to_adversary": to_adv,
        "survivors": survivors,
        "decisions": [asdict(d) for d in decisions],
        "verdicts": verdicts,
        "claims": claims,
    }


def write_gate_record(ws, phase: str, record: dict) -> Path:
    """Persist a gate record to ``kb/gates/<phase>.json`` and return the path."""
    d = ws.kb / "gates"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{phase}.json"
    p.write_text(json.dumps(record, indent=2))
    return p
