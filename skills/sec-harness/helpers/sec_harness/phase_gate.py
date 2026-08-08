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
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


def _parse_ref(ref: str) -> tuple[str, int | None]:
    """Split ``ref`` into ``(path, line)``, accepting a single line or an ``N-M`` range.

    A range citation (``path:43-53``) is anchored on its start line ``N`` — that is the line
    the writer actually pointed at; the range is prose, not something ``ref_resolves`` needs to
    fully bound. Without this, ``rsplit(":", 1)``'s ``tail.isdigit()`` check fails on ``"43-53"``,
    the whole ``:43-53`` suffix is treated as part of the path, and the ref never resolves (the
    "range-ref bug").
    """
    ref = (ref or "").strip()
    if ":" not in ref:
        return ref, None
    head, tail = ref.rsplit(":", 1)
    if tail.isdigit():
        return head, int(tail)
    if "-" in tail:
        start, _, end = tail.partition("-")
        if start.isdigit() and end.isdigit():
            return head, int(start)
    return ref, None


def _line_in_range(fp: Path, line: int) -> bool:
    if not fp.is_file():
        return False
    try:
        n = len(fp.read_text(errors="replace").splitlines())
    except OSError:
        return False
    return 1 <= line <= n


def resolve_ref(root: str | Path, ref: str) -> tuple[bool, str | None]:
    """Resolve ``ref`` against ``root``, falling back to a basename search on nested repos.

    Tries the ref as a direct repo-root-relative path first. If that path segment does not
    exist, falls back to searching for a unique file matching the ref's basename anywhere under
    ``root`` — the pattern seen when an agent cites a package-relative or bare-basename path
    instead of the repo-root-relative convention (``recon.md``/``context-ingest.md`` use it
    correctly; ``architecture.md``/``threat-model.md`` have not always). The fallback only fires
    on a genuine path miss, and only resolves when the basename match is unique — an ambiguous
    basename (two ``main.go`` in different packages) is reported, not guessed.

    Args:
        root: Target repo root.
        ref: A path, optionally suffixed ``:line`` or ``:start-end``.

    Returns:
        ``(resolved, note)`` — ``note`` is ``None`` on a direct hit, or a one-line description
        of the fallback outcome (used, ambiguous, or still missing) worth recording in the gate.
    """
    path, line = _parse_ref(ref)
    if not path:
        return False, None
    root = Path(root)
    fp = root / path
    if fp.exists():
        return (True, None) if line is None else (_line_in_range(fp, line), None)

    basename = Path(path).name
    if not basename or "." not in basename:
        return False, None
    matches = [m for m in root.rglob(basename) if m.is_file()]
    if len(matches) != 1:
        if len(matches) > 1:
            return False, f"basename {basename!r} is ambiguous ({len(matches)} matches) — unresolved"
        return False, None
    resolved_fp = matches[0]
    rel = resolved_fp.relative_to(root)
    note = f"path-relative fallback: {path!r} resolved via basename search to {str(rel)!r}"
    if line is None:
        return True, note
    return _line_in_range(resolved_fp, line), note


def ref_resolves(root: str | Path, ref: str) -> bool:
    """True if ``ref`` points at real code under ``root`` (direct hit or basename fallback).

    Accepts a bare path (file or directory must exist) or a ``file:line``/``file:start-end``
    reference (the file must exist and the line be in range). This is what code can verify about
    an LLM's claim; it never judges whether the analysis is *correct* — that is the adversary's
    job. See :func:`resolve_ref` for the fallback note this discards.

    Args:
        root: Target repo root.
        ref: A repo-relative path, optionally suffixed ``:line`` or ``:start-end``.

    Returns:
        True if the reference resolves to a real file/dir (and in-range line).
    """
    resolved, _ = resolve_ref(root, ref)
    return resolved


@dataclass
class GateDecision:
    """Deterministic verdict for one claim before any adversary runs."""

    claim_id: str
    status: str  # "reject" | "to-adversary"
    reasons: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    text: str = ""
    notes: list[str] = field(default_factory=list)


def run_phase_checks(claims: list[dict], target_root: str | Path) -> list[GateDecision]:
    """Return a :class:`GateDecision` per claim for an analysis/context phase.

    Args:
        claims: Each is ``{"id": str, "text": str, "refs": [path or file:line, ...]}`` — the
            claim's assertion and the code references it rests on.
        target_root: The scanned repo root the references resolve against.

    Returns:
        One decision per claim, in input order. ``reject`` = a hard structural failure (a cited
        reference does not resolve); ``to-adversary`` = well-formed, worth an adversary's time.
        A claim with no refs is sent to the adversary on judgment alone (logged). A ref resolved
        only via :func:`resolve_ref`'s basename fallback stays ``to-adversary`` but records the
        fallback in ``notes`` so silent path-correction stays visible.
    """
    out: list[GateDecision] = []
    for i, claim in enumerate(claims):
        cid = str(claim.get("id", i))
        reasons: list[str] = []
        notes: list[str] = []
        reject = False
        refs = claim.get("refs", [])
        for ref in refs:
            resolved, note = resolve_ref(target_root, ref)
            if not resolved:
                reasons.append(f"ref does not resolve: {ref!r}" + (f" ({note})" if note else ""))
                reject = True
            elif note:
                notes.append(note)
        if not refs:
            reasons.append("no code refs to verify — sent to adversary on judgment alone")
        out.append(GateDecision(cid, "reject" if reject else "to-adversary", reasons,
                                 refs=list(refs), text=str(claim.get("text", "")), notes=notes))
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
        decisions, verdicts, claims, warning}``, where ``claims`` maps each sent-to-adversary
        claim id to its ``{text, refs}`` so the adversary reviews content, not opaque ids, and
        ``warning`` is non-null when every claim was deterministically rejected — a phase that
        would otherwise "pass" a downstream check with nothing ever having reached the
        adversary.
    """
    verdicts = verdicts or {}
    rejected_det = [d.claim_id for d in decisions if d.status == "reject"]
    to_adv = [d.claim_id for d in decisions if d.status == "to-adversary"]
    survivors = [c for c in to_adv if verdicts.get(c, "CONFIRMED") != "INVALIDATED"]
    claims = {d.claim_id: {"text": d.text, "refs": d.refs}
              for d in decisions if d.status == "to-adversary"}
    warning = None
    if decisions and not to_adv:
        warning = (f"sent_to_adversary is empty while claims_in={len(decisions)} — every claim "
                   "was deterministically rejected; treat as a gate failure to investigate, "
                   "not a clean pass")
    return {
        "phase": phase,
        "claims_in": len(decisions),
        "rejected_deterministically": rejected_det,
        "sent_to_adversary": to_adv,
        "survivors": survivors,
        "decisions": [asdict(d) for d in decisions],
        "verdicts": verdicts,
        "claims": claims,
        "warning": warning,
    }


def claims_from_profile(profile) -> list[dict]:
    """Turn a recon ScanProfile into gate claims (one per entrypoint + subsystem).

    Args:
        profile: A :class:`sec_harness.profile.ScanProfile` (or any object exposing the same
            ``entrypoints`` / ``subsystems`` attributes).

    Returns:
        Claims in ``{"id", "text", "refs"}`` form, ready for :func:`run_phase_checks`.
    """
    claims: list[dict] = []
    for i, ep in enumerate(getattr(profile, "entrypoints", []) or []):
        ref = ep.split(":")[0] if isinstance(ep, str) else str(ep)
        claims.append({"id": f"ep-{i}", "text": f"entrypoint {ep}",
                       "refs": [ref] if ref else []})
    for i, s in enumerate(getattr(profile, "subsystems", []) or []):
        name = s.get("name", f"sub-{i}")
        claims.append({"id": f"sub-{i}:{name}",
                       "text": f"subsystem {name}: {s.get('why', '')}",
                       "refs": list(s.get("paths", []))})
    evidence = getattr(profile, "attack_surface_evidence", {}) or {}
    for k in getattr(profile, "attack_surface", []) or []:
        claims.append({"id": f"surf-{k}", "text": f"attack_surface includes {k}",
                       "refs": list(evidence.get(k, []))})
    return claims


def claims_from_context(ctx) -> list[dict]:
    """Turn an ingested Context into gate claims (one per item with a code location).

    Args:
        ctx: A :class:`sec_harness.context.Context` (or any object exposing an ``items``
            list of :class:`~sec_harness.context.ContextItem`-shaped entries).

    Returns:
        Claims in ``{"id", "text", "refs"}`` form, ready for :func:`run_phase_checks`.
    """
    claims: list[dict] = []
    for i, it in enumerate(getattr(ctx, "items", []) or []):
        where = getattr(it, "where", "") or ""
        kind = getattr(it, "kind", "item")
        text = getattr(it, "text", "") or ""
        claims.append({"id": f"ctx-{i}", "text": f"{kind}: {text}".strip(),
                       "refs": [where] if where else []})
    return claims


_MD_CITATION = re.compile(
    r"([\w./-]+\.(?:py|js|ts|tsx|jsx|go|java|rb|php|c|cc|cpp|rs|"
    r"yaml|yml|tf|hcl|tpl|json|sh|puml|dot)):(\d+(?:-\d+)?)"
)


def claims_from_markdown(text: str) -> list[dict]:
    """Extract gate claims from ``path.ext:line`` / ``path.ext:start-end`` citations.

    Recognizes code AND IaC/config/diagram extensions and single-line or range citations
    (a range anchors on its start line). Backtick-wrapped citations are captured (the regex
    is not backtick-anchored). Prose file mentions without a line number are not claims.

    Args:
        text: Markdown/free-text content to scan.

    Returns:
        Claims in ``{"id", "text", "refs"}`` form, one per citation found.
    """
    claims: list[dict] = []
    for line in text.splitlines():
        for m in _MD_CITATION.finditer(line):
            path, lineno = m.group(1), m.group(2)
            start = lineno.split("-", 1)[0]
            claims.append({"id": f"md-{len(claims)}", "text": line.strip(),
                           "refs": [f"{path}:{start}"]})
    return claims


def write_gate_record(ws, phase: str, record: dict) -> Path:
    """Persist a gate record to ``kb/gates/<phase>.json`` and return the path."""
    d = ws.kb / "gates"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{phase}.json"
    p.write_text(json.dumps(record, indent=2))
    return p
