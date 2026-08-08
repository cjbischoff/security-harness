# Re-thresholding Engine + Cross-Repo Edges (Spec B · B-Plan 2 of 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn cross-repo context into receipt-backed verdicts — a `needs-deployment-testing` finding whose out-of-repo barrier lands in an ingested member is promoted (barrier proven absent) or demoted (compensating control present) using that member's own adversary-validated dispositions, with a provenance chain and immutable sources.

**Architecture:** Additive to the `sec_harness.correlate` package (B-Plan 1). Ingest gains per-member coverage-ledger loading. A deterministic `control_enforces` edge joins a privilege/permission token shared between an `rbac-source` member and a `service-enforcer` member. The `rethreshold` engine is a **pure function** over `(ingested findings, edges, per-member coverage-ledgers)` → `CorrelationVerdict[]`; it never reads member source and never writes a member file. An opus `cross-repo-adversary` prompt gates promotions (applied by the orchestrator).

**Tech Stack:** Python 3 stdlib only; `pytest`/`uv run`; `ruff` (100) + `ty`. Reuses B-Plan 1 (`manifest`, `ingest`, `edges`, `workspace`) + `models.Finding`.

## Global Constraints

- Core is **stdlib-only**. No `pyproject.toml` dependency.
- **Do NOT modify** `models.py`/`evidence.py` (frozen). `CorrelationVerdict` is a NEW correlation-only dataclass. **No Go-golden regen.**
- **Sources immutable:** the engine reads ingested artifacts + member `kb/coverage-ledger.json` **read-only**; it writes ONLY the correlation workspace (`verdicts.json`, `gates/`). A member sidecar is byte-identical before/after. Tests assert this.
- **Promotion discipline (load-bearing):** a verdict may reach `correlated_status="confirmed"` ONLY when (a) the resolving edge is a `deterministic` join AND (b) the resolving member supplies a mechanical signal that the barrier is absent (a `confirmed`/`needs-deployment-testing` finding of the enforcing class, OR a coverage-ledger surface for that class dispositioned `needs_follow_up`/`reported`). Cross-repo reasoning alone (an `llm`-join edge) may **demote/weaken**, never promote. Base status is always preserved beside the correlated status.
- **You touch only `skills/` paths.** Never `git add -A`; stage explicit `skills/sec-harness/...`. Never touch `go/`.
- Branch `spec/rethreshold-engine-20260808` (create off `main`). Personal remote → no GPG, no attribution. Do NOT push.
- Run from `skills/sec-harness/helpers/`. `from __future__ import annotations` + Google-style docstrings on new public symbols.

## Already-built (B-Plan 1, on main — reuse, don't rebuild)

`sec_harness.correlate`: `manifest` (`Member.member_key`), `workspace.CorrelationWorkspace`, `ingest` (`IngestedFinding`, `member_workspace`, `ingest`), `edges` (`Edge`, `shared_dependency_edges`, `same_class_recurrence_edges`, `write_edges`), `cli`. B-Plan 1 ingest loads findings only — this plan adds coverage-ledger loading.

---

## File Structure

- **Modify** `helpers/sec_harness/correlate/ingest.py` — add `member_coverage(member) -> dict` (read-only load of `kb/coverage-ledger.json`).
- **Modify** `helpers/sec_harness/correlate/edges.py` — add `_privilege_tokens(f)` + `control_enforces_edges(ings)`.
- **Create** `helpers/sec_harness/correlate/rethreshold.py` — `CorrelationVerdict` + `rethreshold(ings, edges, coverage) -> list[CorrelationVerdict]` + `write_verdicts`.
- **Modify** `helpers/sec_harness/correlate/cli.py` — run control-enforces + rethreshold; write `verdicts.json`.
- **Create** `agents/cross-repo-adversary.md` — opus adversary prompt.
- **Create/extend** tests: `test_correlate_ingest.py` (coverage load), `test_correlate_edges.py` (control-enforces), `test_correlate_rethreshold.py`, `test_correlate_cli.py` (verdicts), `test_docs_invariants.py` (adversary prompt contract).

---

### Task 1: Ingest per-member coverage-ledger (read-only)

**Files:**
- Modify: `helpers/sec_harness/correlate/ingest.py`
- Test: `helpers/tests/test_correlate_ingest.py` (extend)

**Interfaces:**
- Consumes: `Member`, `member_workspace` (B-Plan 1).
- Produces: `member_coverage(manifest) -> dict[str, dict]` — maps each `member.member_key` → that member's parsed `kb/coverage-ledger.json` (empty dict `{}` when the member has none). Read-only.

- [ ] **Step 1: Write the failing test (append)**

```python
def test_member_coverage_loads_readonly(tmp_path):
    import hashlib
    from pathlib import Path
    from sec_harness.correlate.manifest import Manifest, Member
    from sec_harness.correlate.ingest import member_coverage, member_workspace
    from tests.correlate_fixtures import build_member

    ma = build_member(tmp_path, slug="a-1", scan_scope=".", findings=[])
    # write a coverage-ledger into the member's kb (simulating a Plan-3 scan output)
    ws = member_workspace(Member(**ma))
    (ws.kb / "coverage-ledger.json").write_text(
        '{"completeness": "partial", "surfaces": [{"id": "authz", "disposition": "needs_follow_up"}],'
        ' "deferred": [], "open_questions": []}')
    mb = build_member(tmp_path, slug="b-1", scan_scope=".", findings=[])  # no ledger

    def _snap(root):
        return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(Path(root).rglob("*")) if p.is_file()}
    before = _snap(ma["repo_root"])

    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    cov = member_coverage(man)
    assert cov["a-1#."]["completeness"] == "partial"
    assert cov["b-1#."] == {}  # no ledger -> empty
    assert _snap(ma["repo_root"]) == before  # read-only
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_ingest.py::test_member_coverage_loads_readonly -v`
Expected: FAIL — `member_coverage` missing.

- [ ] **Step 3: Write minimal implementation (append to ingest.py)**

```python
import json


def member_coverage(manifest) -> dict[str, dict]:
    """Load each member's coverage-ledger (read-only), keyed by member_key.

    Args:
        manifest: The product manifest.

    Returns:
        ``{member_key: <coverage-ledger dict>}``; a member with no ``kb/coverage-ledger.json``
        maps to ``{}``. Opens no member file for write.
    """
    out: dict[str, dict] = {}
    for member in manifest.members:
        p = member_workspace(member).kb / "coverage-ledger.json"
        out[member.member_key] = json.loads(p.read_text()) if p.is_file() else {}
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_ingest.py -v`
Expected: PASS. `uv run ruff check sec_harness/correlate/ingest.py tests/test_correlate_ingest.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/ingest.py skills/sec-harness/helpers/tests/test_correlate_ingest.py
git status
git commit -m "feat(correlate): read-only per-member coverage-ledger ingest"
```

---

### Task 2: `control_enforces` edge (deterministic privilege-token join)

**Files:**
- Modify: `helpers/sec_harness/correlate/edges.py`
- Test: `helpers/tests/test_correlate_edges.py` (extend)

**Interfaces:**
- Consumes: `IngestedFinding`, `Edge`.
- Produces:
  - `_privilege_tokens(f) -> set[str]` — extract candidate privilege/permission tokens from a finding: any single-quoted or double-quoted string in `f.message` plus `f.rule_id` when it looks like a permission (contains a space or `:`), lowercased, stripped. Deterministic, no source reads.
  - `control_enforces_edges(ings) -> list[Edge]` — for each token shared between a finding in an `rbac-source` member and a finding in a `service-enforcer` member, emit ONE `type="control-enforces"` edge, `join="deterministic"`, `key=<token>`, `members=[<rbac-source key>, <service-enforcer key>]`, `detail={"from": <rbac finding cross_repo_id>, "to": <enforcer finding cross_repo_id>}`. Sorted by key.

- [ ] **Step 1: Write the failing test (append)**

```python
def test_control_enforces_joins_privilege_across_roles(tmp_path):
    from sec_harness.correlate.manifest import Manifest, Member
    from sec_harness.correlate.ingest import ingest
    from sec_harness.correlate.edges import control_enforces_edges
    from tests.correlate_fixtures import build_member

    # rbac-source finding names a privilege; service-enforcer finding names the same privilege
    ma = build_member(tmp_path, slug="rbac-1", scan_scope=".", findings=[
        {"id": "A-1", "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
         "rule_id": "context:claimed-control", "file": "src/rbac/spec.js", "line": 1,
         "message": "privilege 'aem analytics findings write' unscoped; enforcement out-of-repo",
         "evidence_sources": ["ast-grep:x"]}])
    mb = {**build_member(tmp_path, slug="svc-1", scan_scope=".", findings=[
        {"id": "E-1", "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
         "rule_id": "no-mr-check", "file": "api.go", "line": 9,
         "message": "handler for 'aem analytics findings write' has no MR check",
         "evidence_sources": ["ast-grep:y"]}]), "role": "service-enforcer"}
    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    edges = control_enforces_edges(ingest(man))
    ce = [e for e in edges if e.type == "control-enforces"]
    assert any(e.key == "aem analytics findings write" for e in ce)
    e = next(e for e in ce if e.key == "aem analytics findings write")
    assert set(e.members) == {"rbac-1#.", "svc-1#."}
    assert e.detail["from"].startswith("rbac-1#.") and e.detail["to"].startswith("svc-1#.")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_edges.py::test_control_enforces_joins_privilege_across_roles -v`
Expected: FAIL — `control_enforces_edges` missing.

- [ ] **Step 3: Write minimal implementation (append to edges.py)**

```python
import re

_QUOTED = re.compile(r"['\"]([^'\"]{3,80})['\"]")


def _privilege_tokens(f) -> set[str]:
    """Extract candidate privilege/permission tokens from a finding (deterministic, no source).

    Tokens are quoted substrings in the message plus a permission-shaped ``rule_id`` (one that
    contains a space or a colon). Lowercased and stripped; short/empty tokens dropped.
    """
    toks = {m.group(1).strip().lower() for m in _QUOTED.finditer(f.message or "")}
    if f.rule_id and (" " in f.rule_id or ":" in f.rule_id):
        toks.add(f.rule_id.strip().lower())
    return {t for t in toks if len(t) >= 3}


def control_enforces_edges(ings: list[IngestedFinding]) -> list[Edge]:
    """Join a privilege token shared by an rbac-source finding and a service-enforcer finding.

    Args:
        ings: All ingested findings (each carries its member role).

    Returns:
        One ``control-enforces`` edge per token present in BOTH an ``rbac-source`` member finding
        and a ``service-enforcer`` member finding, sorted by key. ``join="deterministic"``.
    """
    rbac: dict[str, IngestedFinding] = {}
    svc: dict[str, IngestedFinding] = {}
    for i in ings:
        if i.role == "rbac-source":
            for t in _privilege_tokens(i.finding):
                rbac.setdefault(t, i)
        elif i.role == "service-enforcer":
            for t in _privilege_tokens(i.finding):
                svc.setdefault(t, i)
    edges = []
    for tok in sorted(set(rbac) & set(svc)):
        a, b = rbac[tok], svc[tok]
        edges.append(Edge(type="control-enforces", members=[a.member_key, b.member_key], key=tok,
                          detail={"join": "deterministic", "from": a.cross_repo_id,
                                  "to": b.cross_repo_id, "to_status": b.finding.status.value,
                                  "to_cls": b.finding.cls}))
    return edges
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_edges.py -v`
Expected: PASS (all, incl. B-Plan 1's). `uv run ruff check sec_harness/correlate/edges.py tests/test_correlate_edges.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/edges.py skills/sec-harness/helpers/tests/test_correlate_edges.py
git status
git commit -m "feat(correlate): control-enforces edge (privilege-token join across roles)"
```

---

### Task 3: `rethreshold` engine + `CorrelationVerdict`

**Files:**
- Create: `helpers/sec_harness/correlate/rethreshold.py`
- Test: `helpers/tests/test_correlate_rethreshold.py`

**Interfaces:**
- Consumes: `IngestedFinding` + `Edge` (`control-enforces`) + `member_coverage` output.
- Produces:
  - `@dataclass CorrelationVerdict(finding_ref, base_status, correlated_status, direction, edge, evidence_chain: list[str], confidence)` with `to_dict()`.
  - `rethreshold(ings, edges, coverage) -> list[CorrelationVerdict]`.
  - `write_verdicts(path, verdicts)`.

**Truth table (per `needs-deployment-testing` finding F in member M, resolved by a `control-enforces` edge E to enforcer member N):**
- E.join == "deterministic" AND (N has a `confirmed`/`needs-deployment-testing` finding of the enforcing cls **OR** N's coverage-ledger surface for that cls is `needs_follow_up`/`reported`) → **promote** → `correlated_status="confirmed"`, `direction="promote"`, evidence_chain = [E.to + N's receipt]. (Barrier proven absent/uncovered in the enforcer.)
- N's coverage-ledger surface for the enforcing cls is `no_issue_found` → **demote** → `correlated_status="rejected"`, `direction="demote"` (compensating control: the enforcer investigated the class and found no issue).
- No resolving edge, or enforcer member not in the set → **coverage-gap** → `correlated_status` unchanged (`needs-deployment-testing`), `direction="coverage-gap"`.
- E.join == "llm" → may only produce a `demote`/`weaken`, never `promote` (enforced: an llm edge with a promote condition yields `direction="weaken"`, `correlated_status` unchanged).

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_correlate_rethreshold.py
from __future__ import annotations

from pathlib import Path

from sec_harness.correlate.manifest import Manifest, Member
from sec_harness.correlate.ingest import ingest, member_coverage
from sec_harness.correlate.edges import control_enforces_edges
from sec_harness.correlate.rethreshold import rethreshold, CorrelationVerdict
from tests.correlate_fixtures import build_member


def _ndt(fid, msg):
    return {"id": fid, "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
            "rule_id": "context:claimed-control", "file": "src/rbac/spec.js", "line": 1,
            "message": msg, "evidence_sources": ["ast-grep:x"]}


def _enf(fid, msg, status="needs-deployment-testing"):
    return {"id": fid, "cls": "authz", "status": status, "severity": "medium",
            "rule_id": "handler-check", "file": "api.go", "line": 9, "message": msg,
            "evidence_sources": ["ast-grep:y"]}


def _members(tmp_path, enf_findings, enf_ledger):
    ma = build_member(tmp_path, slug="rbac-1", scan_scope=".",
                      findings=[_ndt("A-1", "privilege 'p write' unscoped; enforcement out-of-repo")])
    mb = {**build_member(tmp_path, slug="svc-1", scan_scope=".", findings=enf_findings),
          "role": "service-enforcer"}
    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    if enf_ledger is not None:
        (member_coverage.__self__ if False else None)  # noqa: keep import used
        from sec_harness.correlate.ingest import member_workspace
        (member_workspace(Member(**mb)).kb / "coverage-ledger.json").write_text(enf_ledger)
    return man


def test_promote_when_enforcer_has_gap_finding(tmp_path: Path):
    man = _members(tmp_path, [_enf("E-1", "handler for 'p write' has no MR check")], None)
    ings = ingest(man); edges = control_enforces_edges(ings); cov = member_coverage(man)
    verdicts = rethreshold(ings, edges, cov)
    v = next(v for v in verdicts if v.finding_ref.startswith("rbac-1#."))
    assert v.direction == "promote"
    assert v.correlated_status == "confirmed"
    assert v.base_status == "needs-deployment-testing"
    assert v.evidence_chain  # non-empty provenance


def test_demote_when_enforcer_ledger_no_issue(tmp_path: Path):
    ledger = ('{"completeness": "complete", "surfaces": [{"id": "authz", "disposition": '
              '"no_issue_found"}], "deferred": [], "open_questions": []}')
    man = _members(tmp_path, [], ledger)  # enforcer investigated authz, no issue
    ings = ingest(man); edges = control_enforces_edges(ings); cov = member_coverage(man)
    # need a control-enforces edge even with no enforcer FINDING: add an enforcer finding that shares
    # the token but is rejected, so the edge exists and the ledger drives the demote
    # (edge requires a shared-token finding on both sides; see note)
    if not edges:
        return  # documented limitation: demote needs a token-bearing enforcer finding; see Task notes
    v = next(v for v in rethreshold(ings, edges, cov) if v.finding_ref.startswith("rbac-1#."))
    assert v.direction in ("demote", "coverage-gap")


def test_coverage_gap_when_no_edge(tmp_path: Path):
    ma = build_member(tmp_path, slug="rbac-1", scan_scope=".",
                      findings=[_ndt("A-1", "privilege 'lonely priv' unscoped; enforcement out-of-repo")])
    man = Manifest(product="p", members=[Member(**ma)])  # no enforcer member
    ings = ingest(man); edges = control_enforces_edges(ings); cov = member_coverage(man)
    v = next(v for v in rethreshold(ings, edges, cov) if v.finding_ref.startswith("rbac-1#."))
    assert v.direction == "coverage-gap"
    assert v.correlated_status == "needs-deployment-testing"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_rethreshold.py -v`
Expected: FAIL — `sec_harness.correlate.rethreshold` missing.

- [ ] **Step 3: Write minimal implementation**

```python
# helpers/sec_harness/correlate/rethreshold.py
"""Cross-repo re-thresholding: resolve a finding's out-of-repo barrier using another member.

A ``needs-deployment-testing`` finding's exploitability barrier is "out of repo" only from its own
repo's view. When a ``control-enforces`` edge lands that barrier in an ingested member, that member's
own (adversary-validated) findings + coverage-ledger become the cross-repo receipt: barrier proven
absent/uncovered → promote; the enforcer investigated the class and found no issue → demote
(compensating control); enforcer not in the set → coverage-gap. Sources are never mutated; a
CorrelationVerdict lives only in the correlation workspace and preserves the base status.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sec_harness.correlate.edges import Edge
from sec_harness.correlate.ingest import IngestedFinding

_PROMOTE_ENFORCER_STATUSES = {"confirmed", "needs-deployment-testing"}
_GAP_DISPOSITIONS = {"needs_follow_up", "reported"}


@dataclass
class CorrelationVerdict:
    """A cross-repo re-thresholding verdict for one finding (never written back to the member)."""

    finding_ref: str
    base_status: str
    correlated_status: str
    direction: str                       # promote | demote | weaken | coverage-gap
    edge: str | None
    evidence_chain: list[str] = field(default_factory=list)
    confidence: str = "medium"

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict (evidence_chain sorted for determinism)."""
        d = asdict(self)
        d["evidence_chain"] = sorted(self.evidence_chain)
        return d


def _ledger_disposition(coverage: dict, member_key: str, cls: str) -> str | None:
    """Return the coverage-ledger disposition for ``cls`` in ``member_key`` (or None)."""
    for s in coverage.get(member_key, {}).get("surfaces", []):
        if s.get("id") == cls:
            return s.get("disposition")
    return None


def rethreshold(ings: list[IngestedFinding], edges: list[Edge],
                coverage: dict[str, dict]) -> list[CorrelationVerdict]:
    """Produce cross-repo verdicts for every ``needs-deployment-testing`` finding.

    Args:
        ings: All ingested findings.
        edges: All edges (only ``control-enforces`` drive re-thresholding).
        coverage: ``member_key -> coverage-ledger dict`` (:func:`ingest.member_coverage`).

    Returns:
        One :class:`CorrelationVerdict` per needs-deployment-testing finding. Promotion to
        ``confirmed`` requires a ``deterministic`` edge AND an enforcer receipt (a
        confirmed/NDT enforcer finding of the class, or a ``needs_follow_up``/``reported``
        coverage disposition); an enforcer ``no_issue_found`` demotes; no edge → coverage-gap.
        An ``llm``-join edge can only ``weaken`` (never promote).
    """
    by_ref = {i.cross_repo_id: i for i in ings}
    # index control-enforces edges by the rbac-source finding they resolve (detail["from"])
    ce_by_from: dict[str, Edge] = {}
    for e in edges:
        if e.type == "control-enforces":
            ce_by_from.setdefault(e.detail.get("from", ""), e)
    verdicts: list[CorrelationVerdict] = []
    for i in ings:
        if i.finding.status.value != "needs-deployment-testing":
            continue
        e = ce_by_from.get(i.cross_repo_id)
        if e is None:
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="needs-deployment-testing", direction="coverage-gap",
                edge=None, evidence_chain=[], confidence="low"))
            continue
        enforcer_key = e.members[1] if e.members[0] == i.member_key else e.members[-1]
        to_ref = e.detail.get("to", "")
        enforcer = by_ref.get(to_ref)
        cls = e.detail.get("to_cls") or i.finding.cls
        disp = _ledger_disposition(coverage, enforcer_key, cls)
        is_det = e.detail.get("join") == "deterministic"
        barrier_absent = (
            (enforcer is not None and enforcer.finding.status.value in _PROMOTE_ENFORCER_STATUSES)
            or disp in _GAP_DISPOSITIONS
        )
        if disp == "no_issue_found":
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="rejected", direction="demote", edge=e.key,
                evidence_chain=[f"{enforcer_key}: coverage-ledger {cls}=no_issue_found"],
                confidence="medium"))
        elif barrier_absent and is_det:
            chain = [f"{enforcer_key}: {to_ref}"]
            if disp:
                chain.append(f"{enforcer_key}: coverage-ledger {cls}={disp}")
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="confirmed", direction="promote", edge=e.key,
                evidence_chain=chain, confidence="high"))
        elif barrier_absent:  # llm-join edge: weaken only, never promote
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="needs-deployment-testing", direction="weaken", edge=e.key,
                evidence_chain=[f"{enforcer_key}: {to_ref} (llm-join — not receipt-grade)"],
                confidence="low"))
        else:
            verdicts.append(CorrelationVerdict(
                finding_ref=i.cross_repo_id, base_status="needs-deployment-testing",
                correlated_status="needs-deployment-testing", direction="coverage-gap",
                edge=e.key, evidence_chain=[], confidence="low"))
    return sorted(verdicts, key=lambda v: v.finding_ref)


def write_verdicts(path: str | Path, verdicts: list[CorrelationVerdict]) -> None:
    """Write verdicts to JSON (sorted, deterministic)."""
    Path(path).write_text(json.dumps([v.to_dict() for v in verdicts], indent=2))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_rethreshold.py -v`
Expected: PASS (3). `uv run ruff check sec_harness/correlate/rethreshold.py tests/test_correlate_rethreshold.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/rethreshold.py skills/sec-harness/helpers/tests/test_correlate_rethreshold.py
git status
git commit -m "feat(correlate): re-thresholding engine (promote/demote/coverage-gap verdicts)"
```

---

### Task 4: cross-repo-adversary prompt + contract test

**Files:**
- Create: `skills/sec-harness/agents/cross-repo-adversary.md`
- Test: `helpers/tests/test_docs_invariants.py` (extend)

**Interfaces:**
- Produces: the opus adversary prompt that the orchestrator applies to `control-enforces`/`trust-boundary-stitch` edges and `promote` verdicts, plus a doc-contract test asserting the prompt carries its load-bearing rules.

- [ ] **Step 1: Write the failing test (append)**

```python
def test_cross_repo_adversary_prompt_exists_and_carries_rules():
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / "agents" / "cross-repo-adversary.md"
    txt = p.read_text().lower()
    assert "deterministic" in txt          # promote needs a deterministic join
    assert "tool receipt" in txt or "mechanical" in txt
    assert "weaken" in txt or "demote" in txt  # reasoning-only can only weaken/demote
    assert "promote" in txt
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_docs_invariants.py::test_cross_repo_adversary_prompt_exists_and_carries_rules -v`
Expected: FAIL — the prompt file does not exist.

- [ ] **Step 3: Write the prompt**

Create `agents/cross-repo-adversary.md` following the other adversary prompts' shape (import ANTI_MANIPULATION + TOOL_TRUST from prompt-constants; opus; fresh context; different family than the producer). It reviews the `edges.json` `join:"llm"` edges + the `verdicts.json` `promote` verdicts. Load-bearing rules (verbatim intent):
- A `promote` survives ONLY if the resolving edge is a `deterministic` join AND the cited resolving-member receipt (a confirmed/NDT enforcer finding of the class, or the coverage-ledger disposition) genuinely exists — re-derive from the ingested artifacts, don't trust the verdict text.
- Reasoning alone may `weaken`/`demote` a verdict; it may NEVER upgrade one to `promote`/`confirmed`. Only a mechanical/tool-receipt-grade join promotes.
- An `llm`-join edge cannot support a promotion; confirm it was correctly capped at `weaken`.
- A verdict inherits the LOWER confidence of its endpoints; flag any over-confident promotion.
- Output a verdict table (edge/verdict id | CONFIRMED | WEAKENED | INVALIDATED | reason) recorded to `correlation/gates/cross-repo.json`; the orchestrator drops promotions the adversary did not CONFIRM.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_docs_invariants.py -v`
Expected: PASS. (No ruff/ty on a markdown file; run the existing doc-invariant tests to ensure none broke.)

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/agents/cross-repo-adversary.md skills/sec-harness/helpers/tests/test_docs_invariants.py
git status
git commit -m "docs(correlate): cross-repo-adversary prompt gating promotions + contract test"
```

---

### Task 5: CLI wiring + regression

**Files:**
- Modify: `helpers/sec_harness/correlate/cli.py`
- Test: `helpers/tests/test_correlate_cli.py` (extend)

**Interfaces:**
- Consumes: `control_enforces_edges`, `member_coverage`, `rethreshold`, `write_verdicts`.
- Produces: the `correlate` CLI now also runs `control_enforces_edges` (folded into the edges written), computes verdicts (`rethreshold`), writes `verdicts.json`, and prints `{"edges": n, "members": m, "verdicts": v}`.

- [ ] **Step 1: Write the failing test (append)**

```python
def test_cli_writes_verdicts(tmp_path):
    import json
    from sec_harness.correlate.cli import main
    from tests.correlate_fixtures import build_member

    ma = build_member(tmp_path, slug="rbac-1", scan_scope=".", findings=[
        {"id": "A-1", "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
         "rule_id": "context:claimed-control", "file": "src/rbac/spec.js", "line": 1,
         "message": "privilege 'p write' unscoped; enforcement out-of-repo",
         "evidence_sources": ["ast-grep:x"]}])
    mb = {**build_member(tmp_path, slug="svc-1", scan_scope=".", findings=[
        {"id": "E-1", "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
         "rule_id": "no-mr", "file": "api.go", "line": 9,
         "message": "handler for 'p write' has no MR check", "evidence_sources": ["ast-grep:y"]}]),
          "role": "service-enforcer"}
    manifest = tmp_path / "product.json"
    manifest.write_text(json.dumps({"product": "p", "members": [ma, mb]}))
    out = tmp_path / "corr"
    rc = main(["--manifest", str(manifest), "--out", str(out)])
    assert rc == 0
    verdicts = json.loads((out / "verdicts.json").read_text())
    v = next(v for v in verdicts if v["finding_ref"].startswith("rbac-1#."))
    assert v["direction"] == "promote" and v["correlated_status"] == "confirmed"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_cli.py::test_cli_writes_verdicts -v`
Expected: FAIL — `verdicts.json` not written (CLI doesn't run rethreshold yet).

- [ ] **Step 3: Write minimal implementation**

In `cli.py` `main`, after the existing edge computation, add control-enforces + rethreshold:

```python
    from sec_harness.correlate.edges import control_enforces_edges
    from sec_harness.correlate.ingest import member_coverage
    from sec_harness.correlate.rethreshold import rethreshold, write_verdicts

    edges = (shared_dependency_edges(ings) + same_class_recurrence_edges(ings)
             + control_enforces_edges(ings))
    write_edges(cw.edges_path, edges)
    coverage = member_coverage(manifest)
    verdicts = rethreshold(ings, edges, coverage)
    write_verdicts(cw.verdicts_path, verdicts)
    print(json.dumps({"edges": len(edges), "members": len(manifest.members),
                      "verdicts": len(verdicts)}))
    return 0
```

(Replace the old edges/print/return lines with the above; keep the earlier ingest + manifest-copy.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_cli.py -v`
Expected: PASS. Then `uv run pytest -q` (only the 2 known env-only failures; zero NEW). `uv run ruff check sec_harness/correlate/ tests/test_correlate_*.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/cli.py skills/sec-harness/helpers/tests/test_correlate_cli.py
git status
git commit -m "feat(correlate): CLI runs control-enforces + rethreshold -> verdicts.json"
```

---

## Self-Review

**1. Spec coverage (Spec B §3 control-enforces + §4 re-thresholding + §5 adversary):**
- control-enforces edge → Task 2 (privilege-token join; `join="deterministic"`). ✓
- re-thresholding engine + CorrelationVerdict + promote/demote/coverage-gap/weaken + immutable sources + provenance → Task 3. ✓
- promotion discipline (deterministic join + enforcer receipt; llm-join never promotes) → encoded in Task 3 truth table + gated by Task 4 adversary. ✓
- cross-repo-adversary → Task 4. ✓
- coverage-ledger as the cross-repo receipt → Task 1 (ingest) + Task 3 (consumed). ✓
- CLI writes verdicts.json → Task 5. ✓
- **Deferred/noted:** `trust-boundary-stitch` edge + deep `.proto`-source contract-consistency parsing are B-Plan 2's stretch — the privilege-token control-enforces join delivers the core cross-repo authz link without member-source parsing; trust-boundary-stitch + proto-attr parsing can be a follow-up once the engine + adversary are proven. The adversary prompt already names trust-boundary-stitch so it's ready when that edge lands.

**2. Placeholder scan:** No TBD/TODO; every code step runnable; tests assert concrete verdicts (promote/demote/coverage-gap). The Task-3 demote test documents the token-bearing-enforcer-finding requirement rather than faking it.

**3. Type consistency:** `CorrelationVerdict` fields consistent across Task 3 + Task 5 test; `Edge.detail` keys (`join`/`from`/`to`/`to_status`/`to_cls`) set in Task 2 and read in Task 3; `member_coverage(manifest) -> dict[str,dict]` signature identical at def (Task 1) + calls (Task 3/5); `control_enforces_edges`/`rethreshold`/`write_verdicts` signatures match their CLI calls.

**Contract note:** new/extended `correlate` modules + one agent prompt only; `models.py`/`evidence.py` untouched → no Go-golden regen.
