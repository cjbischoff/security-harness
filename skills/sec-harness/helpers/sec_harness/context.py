"""Codebase context ingestion (Phase C1).

Repos carry security-relevant context: design docs, openspec/ADR specs, runbooks,
threat models, prior review notes, prior findings. This module discovers those
sources (deterministic), holds the distilled structure an LLM agent produces
(`agents/context-ingest.md`), and turns it into scan-driving material — hunt rows for
the threat model and control-verification worklist items for investigate.

TRUST: every item is tagged. ``untrusted-doc`` items are LEADS/CLAIMS-to-verify — they
add worklist/hunt items but NEVER suppress a finding and NEVER auto-confirm one. A
"claimed control" only becomes a finding when investigate proves it missing/bypassable
with a tool receipt. ``prior-scan`` items (our own past conclusions) are higher-trust
but still drift-checked. This mirrors ANTI_MANIPULATION: repo prose is data, not proof.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

KINDS = ("trust_boundary", "claimed_control", "prior_finding", "attack_lead",
         "source_pointer", "note")
TRUST = ("untrusted-doc", "prior-scan")
# Verification of a claimed control against code (C1 rework). "" = not yet verified.
VERIFY_STATUS = ("", "PRESENT", "MISSING", "BYPASSABLE")

# Directories/globs that commonly hold security-relevant context. Discovery is
# deterministic; the LLM agent decides what's actually load-bearing.
_CONTEXT_GLOBS = (
    "docs/**/*.md", "openspec/**/*.md", "adr/**/*.md", "adrs/**/*.md",
    "doc/**/*.md", "guides/**/*.md", "rfcs/**/*.md", "spec/**/*.md", "specs/**/*.md",
    "SECURITY.md", "SECURITY.markdown", "THREAT_MODEL.md", "THREATMODEL.md",
    "*security*review*.md", "*e2e-security*.md", "test-findings*.md",
    "claudedocs/**/*.md", "ARCHITECTURE.md", "CONTRIBUTING.md",
)
_DIAGRAM_TEXT_GLOBS = ("**/*.puml", "**/*.dot", "**/*.mmd")
_DIAGRAM_IMAGE_GLOBS = ("**/*.puml.png", "**/*.puml.svg", "**/*.drawio.png")
_SKIP = ("node_modules", "vendor", ".git", "dist", "build", ".sec-harness")
_MAX_FILES = 200


@dataclass
class ContextItem:
    """One distilled piece of context."""

    kind: str            # trust_boundary | claimed_control | prior_finding | attack_lead | ...
    text: str
    trust: str = "untrusted-doc"
    cls: str = ""        # attack class this relates to (when known)
    where: str = ""      # code/doc location it points at (file[:line])
    source_doc: str = ""  # the doc it came from
    verify_hint: str = ""  # for claimed_control: how to check it holds in code
    verify_status: str = ""  # C1 rework: PRESENT | MISSING | BYPASSABLE | "" (unverified)

    def validate(self) -> list[str]:
        errs = []
        if self.kind not in KINDS:
            errs.append(f"bad kind {self.kind!r}")
        if self.trust not in TRUST:
            errs.append(f"bad trust {self.trust!r}")
        if self.verify_status not in VERIFY_STATUS:
            errs.append(f"bad verify_status {self.verify_status!r}")
        if not self.text.strip():
            errs.append("empty text")
        return errs


@dataclass
class Context:
    """Distilled repo context + provenance."""

    items: list[ContextItem] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)  # {docs_read[], prior_scans_read[], sha}

    def of_kind(self, kind: str) -> list[ContextItem]:
        return [i for i in self.items if i.kind == kind]

    def validate(self) -> list[str]:
        errs = []
        for i in self.items:
            errs += i.validate()
        return errs

    def to_dict(self) -> dict:
        return {"items": [asdict(i) for i in self.items], "provenance": self.provenance}

    @classmethod
    def from_dict(cls, d: dict) -> Context:
        items = [ContextItem(**{k: v for k, v in i.items() if k in ContextItem.__dataclass_fields__})
                 for i in d.get("items", [])]
        return cls(items=items, provenance=d.get("provenance", {}))


def discover_context_files(repo_root: str | Path, scan_scope: str = ".") -> list[str]:
    """Return repo-root-relative candidate context docs (deterministic, capped).

    Globs from ``repo_root`` (not a sub-path), so a monorepo sub-service scan also finds
    the service's docs at the repo root. Includes narrative ``.md``, plain-text diagrams
    (``.puml``/``.dot``/``.mmd`` — machine-readable), and canonical monorepo service-doc dirs
    derived from ``scan_scope``. Image-only diagrams (``.puml.png``/``.svg``) are returned too
    so the caller can record them as coverage items rather than silently skipping them.

    Args:
        repo_root: The git top-level (canonical resolution base).
        scan_scope: Target path relative to ``repo_root`` ("." for a whole-repo scan).

    Returns:
        Sorted, de-duplicated repo-root-relative paths (≤ ``_MAX_FILES``).
    """
    root = Path(repo_root)
    found: set[str] = set()
    globs = _CONTEXT_GLOBS + _DIAGRAM_TEXT_GLOBS + _DIAGRAM_IMAGE_GLOBS
    for pat in globs:
        for p in root.glob(pat):
            if p.is_file() and not any(s in p.parts for s in _SKIP):
                found.add(p.relative_to(root).as_posix())
    # scan_scope sub-tree + canonical monorepo service-doc dirs for a sub-service scan
    if scan_scope != ".":
        for p in (root / scan_scope).glob("**/*.md"):
            if p.is_file() and not any(s in p.parts for s in _SKIP):
                found.add(p.relative_to(root).as_posix())
        svc = Path(scan_scope).name
        for base in (f"docs/services/{svc}", f"docs/global-services/{svc}", f"docs/{svc}"):
            for p in (root / base).glob("**/*.md"):
                if p.is_file() and not any(s in p.parts for s in _SKIP):
                    found.add(p.relative_to(root).as_posix())
    return sorted(found)[:_MAX_FILES]


def context_path(ws) -> Path:
    """Path to the volatile per-scan context.json in the KB."""
    return ws.kb / "context.json"


def prior_context_path(ws) -> Path:
    """Path to the durable cross-scan prior_context.json in the KB."""
    return ws.kb / "prior_context.json"


def save(ws, ctx: Context) -> None:
    """Persist context.json + a rendered CONTEXT.md."""
    ws.kb.mkdir(parents=True, exist_ok=True)
    context_path(ws).write_text(json.dumps(ctx.to_dict(), indent=2))
    (ws.kb / "CONTEXT.md").write_text(render_markdown(ctx))


def load(ws) -> Context:
    """Load context.json (empty Context if absent)."""
    p = context_path(ws)
    return Context.from_dict(json.loads(p.read_text())) if p.exists() else Context()


def render_markdown(ctx: Context) -> str:
    """Human-readable CONTEXT.md."""
    lines = ["# Ingested context", "",
             ("_Distilled from repo docs + prior scans. **Untrusted leads / claims to "
              "verify** — never a safe-list; a claimed control is a finding only if proven "
              "missing in code._"), ""]
    for kind, title in (("trust_boundary", "Trust boundaries"),
                        ("claimed_control", "Claimed controls (verify in code)"),
                        ("prior_finding", "Prior findings (re-check)"),
                        ("attack_lead", "Attack leads"),
                        ("source_pointer", "Source pointers"),
                        ("note", "Notes")):
        items = ctx.of_kind(kind)
        if not items:
            continue
        lines += [f"## {title}", ""]
        for i in items:
            loc = f" — `{i.where}`" if i.where else ""
            src = f" _(src: {i.source_doc}, {i.trust})_" if i.source_doc else f" _({i.trust})_"
            lines.append(f"- {i.text}{loc}{src}")
        lines.append("")
    return "\n".join(lines) + "\n"


# ---- driving helpers (turn context into scan-driving material) ----

def hunt_rows(ctx: Context) -> list[dict]:
    """Trust boundaries + claimed controls → prioritized threat-model hunt rows."""
    rows = []
    for i in ctx.of_kind("trust_boundary"):
        rows.append({"cls": i.cls or "authz", "where": i.where,
                     "why": f"trust boundary: {i.text}", "trust": i.trust})
    for i in ctx.of_kind("claimed_control"):
        rows.append({"cls": i.cls or "authz", "where": i.where,
                     "why": f"verify claimed control: {i.text} ({i.verify_hint})".strip(),
                     "trust": i.trust})
    return rows


def control_worklist(ctx: Context) -> list[dict]:
    """Claimed controls → investigate control-verification worklist items.

    Each item asks the class agent to PROVE the control exists + is effective; a
    missing/bypassable control is a finding, a present one is recorded (not a finding).
    """
    return [{"control": i.text, "cls": i.cls, "where": i.where,
             "verify_hint": i.verify_hint, "source": i.source_doc, "trust": i.trust}
            for i in ctx.of_kind("claimed_control")]


def leads(ctx: Context) -> list[ContextItem]:
    """Raw attack leads (extra investigate candidates)."""
    return ctx.of_kind("attack_lead")


def _split_where(where: str) -> tuple[str, int]:
    """Split a ``file[:line]`` (or bare path) into ``(file, line)``; line defaults to 1."""
    where = (where or "").strip()
    if ":" in where:
        head, tail = where.rsplit(":", 1)
        if tail.isdigit():
            return head, int(tail)
    return where or "(unknown)", 1


def control_findings(ctx: Context, discovery_sha: str | None = None) -> list:
    """Turn MISSING/BYPASSABLE verified claimed-controls into CANDIDATE findings (C1 rework).

    A claimed control the code does not enforce is a lead worth a finding — but only a
    CANDIDATE: its sole evidence is a doc claim (``llm-claimed:doc-claim``), so it cannot
    reach ``confirmed`` until investigate proves it missing with a tool receipt. PRESENT and
    unverified controls produce no finding. This preserves the trust contract in code.

    Args:
        ctx: The verified context (claimed_control items carry ``verify_status``).
        discovery_sha: Git SHA to stamp on the candidate findings.

    Returns:
        A list of :class:`sec_harness.models.Finding` in CANDIDATE status, id ``CTL-####``.
    """
    from sec_harness.models import Finding, FindingStatus, Severity

    out = []
    n = 0
    for i in ctx.of_kind("claimed_control"):
        if i.verify_status not in ("MISSING", "BYPASSABLE"):
            continue
        n += 1
        file, line = _split_where(i.where)
        out.append(Finding(
            id=f"CTL-{n:04d}", rule_id="context:claimed-control", cls=i.cls or "authz",
            status=FindingStatus.CANDIDATE, severity=Severity.MEDIUM,
            file=file, line=line,
            message=f"claimed control not enforced in code ({i.verify_status}): {i.text}",
            evidence_sources=["llm-claimed:doc-claim"], discovery_sha=discovery_sha,
            history=[{"event": "context:control-verification",
                      "verify_status": i.verify_status, "source_doc": i.source_doc}],
        ))
    return out


def manual_review_findings(ctx: Context, discovery_sha: str | None = None) -> list:
    """Turn attack-lead context items into NEEDS_DEPLOYMENT_TESTING findings (O-020).

    A repo doc's attack lead (e.g. "CI deploy-token reachable via webhook") is not a
    tool-confirmed finding, but it is a real lead a human should chase — dropping it
    silently loses signal. Carrying it as a finding gets it into the red-team plan's
    manual test section instead of vanishing after context ingestion.

    Args:
        ctx: The ingested context (``attack_lead`` items).
        discovery_sha: Git SHA to stamp on the LEAD findings.

    Returns:
        A list of :class:`sec_harness.models.Finding` in NEEDS_DEPLOYMENT_TESTING
        status, id ``LEAD-####``.
    """
    from sec_harness.models import Finding, FindingStatus, Severity

    out = []
    for n, i in enumerate(ctx.of_kind("attack_lead"), start=1):
        file, line = _split_where(i.where)
        out.append(Finding(
            id=f"LEAD-{n:04d}", rule_id="context:attack-lead", cls="manual-review",
            status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.MEDIUM,
            file=file, line=line, message=i.text,
            evidence_sources=["llm-claimed:doc-lead"], discovery_sha=discovery_sha,
            history=[{"event": "context:attack-lead", "source_doc": i.source_doc}],
        ))
    return out
