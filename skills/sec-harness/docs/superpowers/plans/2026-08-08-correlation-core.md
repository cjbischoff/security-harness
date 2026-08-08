# Correlation Core (Spec B · B-Plan 1 of 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the read-only multi-repo correlation core — a product manifest, a `CorrelationWorkspace`, read-only ingest of N per-repo sidecars, and the two purely-deterministic cross-repo joins (shared-dependency roll-up, same-class recurrence) — written to `edges.json` via a `correlate` CLI.

**Architecture:** A new stdlib-only `sec_harness.correlate` package. It locates each member's sidecar via Plan 1's `RepoMemory.for_target(repo_root/scan_scope)`, reads its findings **read-only** (never opens a member file for write), tags each finding with a member key `<slug>#<scan_scope>` and cross-repo id, then runs two deterministic joins over the ingested findings. No LLM, no member-source reads, no re-thresholding — those are B-Plan 2/3.

**Tech Stack:** Python 3 stdlib only; `pytest` via `uv run`; `ruff` (line-length 100) + `ty`. Reuses `sec_harness.models.Finding`, `sec_harness.workspace.read_findings`, `sec_harness.repo_memory.RepoMemory`.

## Global Constraints

- Core is **stdlib-only**. Add NO runtime dependency to `pyproject.toml`.
- **Do NOT modify** `models.py` or `evidence.py` (frozen contract). B-Plan 1 adds a NEW `correlate` package + a NEW `CorrelationVerdict`/edge dataclass; it touches neither frozen file. **No Go-golden regen.**
- **Immutability invariant:** the correlation layer opens NO member-repo file for write. A member's `.sec-harness/<slug>/` is byte-identical before and after a correlation run. Tests must assert this.
- **You touch only `skills/` paths.** Never `git add -A`; stage explicit `skills/sec-harness/...` paths; `git status` shows only skill paths before every commit. Never touch `go/`.
- Work on branch `spec/cross-repo-correlation-20260808` (already created off `main`). Personal remote → no GPG, no AI attribution. Do NOT push.
- Run from `skills/sec-harness/helpers/`. Tests in `helpers/tests/`. `uv run pytest`.
- New modules start with `from __future__ import annotations` + Google-style docstrings on public functions/classes.
- **Deterministic only:** every join in B-Plan 1 is a pure function of ingested findings — no LLM, no network, no member-source access. (Contract-consistency + fuzzy edges + re-thresholding are B-Plan 2, resequenced here because they need member-source reads.)

---

## File Structure

- **Create** `helpers/sec_harness/correlate/__init__.py` — package marker + public exports.
- **Create** `helpers/sec_harness/correlate/manifest.py` — `Member`, `Manifest`, `load_manifest`, `validate_manifest`.
- **Create** `helpers/sec_harness/correlate/workspace.py` — `CorrelationWorkspace` (dir layout) + `member_key`/`cross_repo_id` helpers.
- **Create** `helpers/sec_harness/correlate/ingest.py` — `ingest(manifest) -> list[IngestedFinding]` (read-only).
- **Create** `helpers/sec_harness/correlate/edges.py` — `Edge` dataclass + `shared_dependency_edges`, `same_class_recurrence_edges`, `write_edges`.
- **Create** `helpers/sec_harness/correlate/cli.py` — `python -m sec_harness.correlate` entrypoint.
- **Create** `helpers/tests/test_correlate_manifest.py`, `test_correlate_ingest.py`, `test_correlate_edges.py`, `test_correlate_cli.py`.
- **Create** `helpers/tests/correlate_fixtures.py` — builds synthetic member sidecars in a tmp dir (shared test helper).

---

### Task 1: Manifest schema + loader

**Files:**
- Create: `helpers/sec_harness/correlate/__init__.py`, `helpers/sec_harness/correlate/manifest.py`
- Test: `helpers/tests/test_correlate_manifest.py`

**Interfaces:**
- Produces:
  - `@dataclass Member(slug: str, repo_root: str, scan_scope: str, role: str)` with `member_key` property = `f"{slug}#{scan_scope}"`.
  - `@dataclass Manifest(product: str, members: list[Member])`.
  - `ROLES = ("rbac-source", "service-enforcer", "infra")`.
  - `load_manifest(path) -> Manifest` (raises `ValueError` on invalid).
  - `validate_manifest(d: dict) -> list[str]` (empty == valid).

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_correlate_manifest.py
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sec_harness.correlate.manifest import Member, Manifest, load_manifest, validate_manifest


def _doc(**kw) -> dict:
    d = {"product": "p", "members": [
        {"slug": "a-1", "repo_root": "/r/a", "scan_scope": ".", "role": "rbac-source"},
        {"slug": "go-1", "repo_root": "/r/go", "scan_scope": "internal/svc", "role": "service-enforcer"},
    ]}
    d.update(kw)
    return d


def test_member_key_disambiguates_monorepo_subdirs():
    m1 = Member(slug="go-1", repo_root="/r/go", scan_scope="internal/svcA", role="service-enforcer")
    m2 = Member(slug="go-1", repo_root="/r/go", scan_scope="internal/svcB", role="service-enforcer")
    assert m1.member_key == "go-1#internal/svcA"
    assert m1.member_key != m2.member_key  # shared slug, distinct member key


def test_load_valid(tmp_path: Path):
    p = tmp_path / "product.json"; p.write_text(json.dumps(_doc()))
    man = load_manifest(p)
    assert man.product == "p"
    assert [m.role for m in man.members] == ["rbac-source", "service-enforcer"]


def test_validate_rejects_bad_role():
    errs = validate_manifest(_doc(members=[{"slug": "a", "repo_root": "/r", "scan_scope": ".",
                                            "role": "bogus"}]))
    assert any("role" in e for e in errs)


def test_validate_requires_members():
    assert any("members" in e for e in validate_manifest({"product": "p", "members": []}))


def test_load_invalid_raises(tmp_path: Path):
    p = tmp_path / "bad.json"; p.write_text(json.dumps({"product": "p", "members": [{"slug": "a"}]}))
    with pytest.raises(ValueError):
        load_manifest(p)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_manifest.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'sec_harness.correlate'`.

- [ ] **Step 3: Write minimal implementation**

```python
# helpers/sec_harness/correlate/__init__.py
"""Read-only multi-repo correlation layer (Spec B).

Joins N per-repo sec-harness scans of one product into a cross-repo view. B-Plan 1 provides
the manifest, workspace, read-only ingest, and the two deterministic findings-joins
(shared-dependency, same-class recurrence). Re-thresholding, source-reading edges, and the
combined artifacts are B-Plan 2/3.
"""

from __future__ import annotations
```

```python
# helpers/sec_harness/correlate/manifest.py
"""Product manifest: the explicit set of member repos (with roles) to correlate."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROLES = ("rbac-source", "service-enforcer", "infra")


@dataclass
class Member:
    """One repo (or monorepo sub-service) participating in a product correlation.

    Attributes:
        slug: The member's ``repo_slug`` (Plan 1). May be shared by two monorepo sub-services.
        repo_root: Absolute git top-level of the member.
        scan_scope: Path relative to ``repo_root`` scanned ("." for a whole repo).
        role: One of :data:`ROLES` — drives the contract-consistency lattice (B-Plan 2).
    """

    slug: str
    repo_root: str
    scan_scope: str
    role: str

    @property
    def member_key(self) -> str:
        """Unique key ``<slug>#<scan_scope>`` (disambiguates monorepo sub-services)."""
        return f"{self.slug}#{self.scan_scope}"


@dataclass
class Manifest:
    """A product's correlation membership."""

    product: str
    members: list[Member]


def validate_manifest(d: dict) -> list[str]:
    """Validate a manifest dict; empty list == valid.

    Args:
        d: Parsed manifest dict.

    Returns:
        Human-readable error strings.
    """
    errs: list[str] = []
    if not isinstance(d.get("product"), str) or not d.get("product"):
        errs.append("manifest.product must be a non-empty string")
    members = d.get("members")
    if not isinstance(members, list) or not members:
        errs.append("manifest.members must be a non-empty list")
        members = []
    for i, m in enumerate(members):
        if not isinstance(m, dict):
            errs.append(f"members[{i}] must be an object")
            continue
        for key in ("slug", "repo_root", "scan_scope", "role"):
            if not isinstance(m.get(key), str) or not m.get(key):
                errs.append(f"members[{i}].{key} must be a non-empty string")
        if m.get("role") not in ROLES:
            errs.append(f"members[{i}].role must be one of {list(ROLES)}")
    return errs


def load_manifest(path: str | Path) -> Manifest:
    """Load + validate a product manifest JSON file.

    Args:
        path: Path to ``product.json``.

    Returns:
        The parsed :class:`Manifest`.

    Raises:
        ValueError: If the manifest fails validation.
    """
    d = json.loads(Path(path).read_text())
    errs = validate_manifest(d)
    if errs:
        raise ValueError("invalid manifest: " + "; ".join(errs))
    return Manifest(product=d["product"],
                    members=[Member(slug=m["slug"], repo_root=m["repo_root"],
                                    scan_scope=m["scan_scope"], role=m["role"])
                             for m in d["members"]])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_manifest.py -v`
Expected: PASS (5). `uv run ruff check sec_harness/correlate/ tests/test_correlate_manifest.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/__init__.py skills/sec-harness/helpers/sec_harness/correlate/manifest.py skills/sec-harness/helpers/tests/test_correlate_manifest.py
git status
git commit -m "feat(correlate): product manifest schema + loader with role validation"
```

---

### Task 2: CorrelationWorkspace + fixture helper

**Files:**
- Create: `helpers/sec_harness/correlate/workspace.py`
- Create: `helpers/tests/correlate_fixtures.py`
- Test: `helpers/tests/test_correlate_ingest.py` (fixture smoke test only in this task)

**Interfaces:**
- Produces:
  - `@dataclass CorrelationWorkspace(root: Path)` with properties `edges_path` (`root/edges.json`), `verdicts_path` (`root/verdicts.json`), `gates_dir` (`root/gates`), `artifacts_dir` (`root/artifacts`), `manifest_path` (`root/product.json`); `ensure()` creates the tree.
  - `correlate_fixtures.build_member(base: Path, *, slug, scan_scope, findings: list[dict]) -> dict` — writes a synthetic member sidecar (a `RepoMemory` workspace) under `base` and returns a manifest-member dict. Used by ingest/edge tests.

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_correlate_ingest.py  (fixture smoke portion; ingest tests added in Task 3)
from __future__ import annotations

from pathlib import Path

from sec_harness.correlate.workspace import CorrelationWorkspace
from tests.correlate_fixtures import build_member
from sec_harness.repo_memory import RepoMemory
from sec_harness.workspace import read_findings


def test_correlation_workspace_layout(tmp_path: Path):
    cw = CorrelationWorkspace(tmp_path / "corr")
    cw.ensure()
    assert cw.edges_path == tmp_path / "corr" / "edges.json"
    assert cw.gates_dir.is_dir()
    assert cw.artifacts_dir.is_dir()


def test_fixture_builds_readable_member(tmp_path: Path):
    m = build_member(tmp_path, slug="a-1", scan_scope=".",
                     findings=[{"id": "C-1", "cls": "deps", "status": "confirmed",
                                "severity": "low", "rule_id": "osv:GHSA-x", "file": "package-lock.json",
                                "line": 1, "message": "vuln", "evidence_sources": ["sca:osv:GHSA-x"]}])
    # the fixture returns a manifest-member dict pointing at the sidecar
    assert m["slug"] == "a-1" and m["scan_scope"] == "."
    rm = RepoMemory.for_target(Path(m["repo_root"]) / m["scan_scope"] if m["scan_scope"] != "."
                               else m["repo_root"])
    assert any(f.id == "C-1" for f in read_findings(rm.workspace))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_ingest.py -v`
Expected: FAIL with `ModuleNotFoundError` for `sec_harness.correlate.workspace` / `tests.correlate_fixtures`.

- [ ] **Step 3: Write minimal implementation**

```python
# helpers/sec_harness/correlate/workspace.py
"""The correlation workspace: a dir holding the manifest, edge graph, verdicts, and artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class CorrelationWorkspace:
    """Filesystem layout for one product's correlation outputs (spans repos)."""

    root: Path

    def __post_init__(self) -> None:
        """Coerce ``root`` to :class:`Path`."""
        self.root = Path(self.root)

    @property
    def manifest_path(self) -> Path:
        """Path to the product manifest copy."""
        return self.root / "product.json"

    @property
    def edges_path(self) -> Path:
        """Path to the cross-repo edge graph."""
        return self.root / "edges.json"

    @property
    def verdicts_path(self) -> Path:
        """Path to the correlation verdicts (B-Plan 2)."""
        return self.root / "verdicts.json"

    @property
    def gates_dir(self) -> Path:
        """Directory for adversary gate records (B-Plan 2)."""
        return self.root / "gates"

    @property
    def artifacts_dir(self) -> Path:
        """Directory for the combined artifacts (B-Plan 3)."""
        return self.root / "artifacts"

    def ensure(self) -> None:
        """Create the correlation workspace tree if absent."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.gates_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
```

```python
# helpers/tests/correlate_fixtures.py
"""Build synthetic member sidecars for correlation tests (no real repos needed)."""

from __future__ import annotations

from pathlib import Path

from sec_harness.models import Finding
from sec_harness.repo_memory import RepoMemory
from sec_harness.workspace import write_findings


def build_member(base: Path, *, slug: str, scan_scope: str, findings: list[dict]) -> dict:
    """Create a member sidecar under ``base`` and return its manifest-member dict.

    The sidecar is a real :class:`RepoMemory` workspace so ingest reads it exactly as it would a
    production one. ``slug`` is used as the repo-root directory name for test isolation.

    Args:
        base: tmp dir to build under.
        slug: member slug (also the repo-root dir name).
        scan_scope: "." or a subpath.
        findings: list of Finding dicts (``Finding.from_dict`` shape).

    Returns:
        A manifest-member dict ``{slug, repo_root, scan_scope, role}`` (role defaults rbac-source;
        override in the returned dict as needed).
    """
    repo_root = base / slug
    target = repo_root if scan_scope == "." else repo_root / scan_scope
    target.mkdir(parents=True, exist_ok=True)
    rm = RepoMemory(root=repo_root / ".sec-harness" / slug)
    rm.workspace.ensure()
    write_findings(rm.workspace, [Finding.from_dict(f) for f in findings])
    return {"slug": slug, "repo_root": str(repo_root), "scan_scope": scan_scope,
            "role": "rbac-source"}
```

Note: the fixture pins the sidecar path directly (`RepoMemory(root=...)`) so a test does not depend on `repo_slug`'s git resolution. Ingest (Task 3) must locate the sidecar the SAME way — see Task 3's `member_workspace`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_ingest.py -v`
Expected: PASS (2). `uv run ruff check sec_harness/correlate/workspace.py tests/correlate_fixtures.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/workspace.py skills/sec-harness/helpers/tests/correlate_fixtures.py skills/sec-harness/helpers/tests/test_correlate_ingest.py
git status
git commit -m "feat(correlate): CorrelationWorkspace layout + synthetic-member test fixture"
```

---

### Task 3: Read-only ingest

**Files:**
- Create: `helpers/sec_harness/correlate/ingest.py`
- Test: `helpers/tests/test_correlate_ingest.py` (extend)

**Interfaces:**
- Consumes: `Manifest`/`Member` (Task 1); `RepoMemory` + `read_findings`.
- Produces:
  - `@dataclass IngestedFinding(member_key: str, role: str, cross_repo_id: str, finding: Finding)`.
  - `member_workspace(member: Member) -> Workspace` — resolves the member's sidecar (`RepoMemory(root=Path(repo_root)/".sec-harness"/slug).workspace`; matches the fixture + production sidecar path).
  - `ingest(manifest: Manifest) -> list[IngestedFinding]` — read-only; each finding tagged `cross_repo_id = f"{member.member_key}:{f.file}:{f.line}:{f.rule_id}"`.

- [ ] **Step 1: Write the failing test (append to test_correlate_ingest.py)**

```python
def test_ingest_tags_cross_repo_ids_readonly(tmp_path: Path):
    import json, hashlib
    from sec_harness.correlate.manifest import Manifest, Member
    from sec_harness.correlate.ingest import ingest

    ma = build_member(tmp_path, slug="a-1", scan_scope=".",
                      findings=[{"id": "C-1", "cls": "deps", "status": "confirmed", "severity": "low",
                                 "rule_id": "osv:GHSA-x", "file": "package-lock.json", "line": 1,
                                 "message": "m", "evidence_sources": ["sca:osv:GHSA-x"]}])
    mb = build_member(tmp_path, slug="go-1", scan_scope="internal/svc",
                      findings=[{"id": "N-1", "cls": "authz", "status": "needs-deployment-testing",
                                 "severity": "medium", "rule_id": "r", "file": "api.go", "line": 9,
                                 "message": "m", "evidence_sources": ["ast-grep:x"]}])
    man = Manifest(product="p", members=[Member(**ma), Member(**{**mb, "role": "service-enforcer"})])

    # snapshot member sidecars to assert immutability
    def _snap(root: Path):
        return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(root.rglob("*")) if p.is_file()}
    before = {ma["slug"]: _snap(Path(ma["repo_root"])), mb["slug"]: _snap(Path(mb["repo_root"]))}

    ings = ingest(man)
    ids = {i.cross_repo_id for i in ings}
    assert "a-1#.:package-lock.json:1:osv:GHSA-x" in ids
    assert "go-1#internal/svc:api.go:9:r" in ids
    assert {i.role for i in ings} == {"rbac-source", "service-enforcer"}

    after = {ma["slug"]: _snap(Path(ma["repo_root"])), mb["slug"]: _snap(Path(mb["repo_root"]))}
    assert before == after, "ingest must not modify any member sidecar"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_ingest.py::test_ingest_tags_cross_repo_ids_readonly -v`
Expected: FAIL — `sec_harness.correlate.ingest` missing.

- [ ] **Step 3: Write minimal implementation**

```python
# helpers/sec_harness/correlate/ingest.py
"""Read-only ingest of member sidecars into cross-repo-tagged findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sec_harness.correlate.manifest import Manifest, Member
from sec_harness.models import Finding
from sec_harness.repo_memory import RepoMemory
from sec_harness.workspace import Workspace, read_findings


@dataclass
class IngestedFinding:
    """A member finding tagged with its cross-repo identity."""

    member_key: str
    role: str
    cross_repo_id: str
    finding: Finding


def member_workspace(member: Member) -> Workspace:
    """Resolve a member's sidecar Workspace (read-only use).

    The sidecar lives at ``<repo_root>/.sec-harness/<slug>/`` — the same location a scan wrote it.

    Args:
        member: The manifest member.

    Returns:
        The member's campaign :class:`Workspace`.
    """
    return RepoMemory(root=Path(member.repo_root) / ".sec-harness" / member.slug).workspace


def ingest(manifest: Manifest) -> list[IngestedFinding]:
    """Read every member's findings read-only, tagged with a cross-repo id.

    Args:
        manifest: The product manifest.

    Returns:
        All members' findings as :class:`IngestedFinding` (empty if a member has none). Opens no
        member file for write.
    """
    out: list[IngestedFinding] = []
    for member in manifest.members:
        ws = member_workspace(member)
        for f in read_findings(ws):
            cid = f"{member.member_key}:{f.file}:{f.line}:{f.rule_id}"
            out.append(IngestedFinding(member_key=member.member_key, role=member.role,
                                       cross_repo_id=cid, finding=f))
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
git commit -m "feat(correlate): read-only ingest tagging findings with cross-repo ids"
```

---

### Task 4: shared-dependency roll-up

**Files:**
- Create: `helpers/sec_harness/correlate/edges.py`
- Test: `helpers/tests/test_correlate_edges.py`

**Interfaces:**
- Consumes: `IngestedFinding` (Task 3).
- Produces:
  - `@dataclass Edge(type: str, members: list[str], key: str, detail: dict)` with `to_dict()`.
  - `shared_dependency_edges(ings: list[IngestedFinding]) -> list[Edge]` — group `cls=="deps"` findings by OSV id (parsed from `rule_id`/`evidence_sources` — the token after the last `:` of an `osv:`/`sca:osv:` source); emit ONE edge per OSV id present in ≥2 distinct member_keys, `type="shared-dependency"`, `key=<osv-id>`, `detail={"reachability": {member_key: severity, ...}}`.

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_correlate_edges.py
from __future__ import annotations

from pathlib import Path

from sec_harness.correlate.manifest import Manifest, Member
from sec_harness.correlate.ingest import ingest
from sec_harness.correlate.edges import shared_dependency_edges
from tests.correlate_fixtures import build_member


def _dep(fid, osv, sev="low"):
    return {"id": fid, "cls": "deps", "status": "confirmed", "severity": sev,
            "rule_id": f"osv:{osv}", "file": "lock", "line": 1, "message": "m",
            "evidence_sources": [f"sca:osv:{osv}"]}


def test_shared_dependency_rolls_up_across_members(tmp_path: Path):
    ma = build_member(tmp_path, slug="a-1", scan_scope=".", findings=[_dep("C-1", "GHSA-shared")])
    mb = build_member(tmp_path, slug="b-1", scan_scope=".", findings=[_dep("C-9", "GHSA-shared"),
                                                                       _dep("C-8", "GHSA-solo")])
    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    edges = shared_dependency_edges(ingest(man))
    shared = [e for e in edges if e.key == "GHSA-shared"]
    assert len(shared) == 1
    assert set(shared[0].members) == {"a-1#.", "b-1#."}
    # GHSA-solo appears in only one member -> not a shared edge
    assert not any(e.key == "GHSA-solo" for e in edges)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_edges.py -v`
Expected: FAIL — `sec_harness.correlate.edges` missing.

- [ ] **Step 3: Write minimal implementation**

```python
# helpers/sec_harness/correlate/edges.py
"""Deterministic cross-repo edges over ingested findings (B-Plan 1: no LLM, no source reads)."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sec_harness.correlate.ingest import IngestedFinding


@dataclass
class Edge:
    """One cross-repo edge over ingested findings."""

    type: str
    members: list[str]          # member_keys the edge spans
    key: str                    # the join key (OSV id, cls+shape, ...)
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict (members sorted for determinism)."""
        d = asdict(self)
        d["members"] = sorted(self.members)
        return d


def _osv_id(f) -> str | None:
    """Extract the OSV id from a deps finding's rule_id / evidence_sources, or None."""
    if f.rule_id.startswith("osv:"):
        return f.rule_id.split(":", 1)[1]
    for s in f.evidence_sources:
        if s.startswith("sca:osv:"):
            return s.split("sca:osv:", 1)[1]
        if s.startswith("osv:"):
            return s.split("osv:", 1)[1]
    return None


def shared_dependency_edges(ings: list[IngestedFinding]) -> list[Edge]:
    """Roll up the same OSV vulnerability seen across ≥2 members into one edge.

    Args:
        ings: All ingested findings.

    Returns:
        One ``shared-dependency`` edge per OSV id present in ≥2 distinct member keys, sorted by key.
        ``detail.reachability`` maps each member key to that member's severity for the dep.
    """
    by_osv: dict[str, dict[str, str]] = defaultdict(dict)
    for i in ings:
        if i.finding.cls != "deps":
            continue
        osv = _osv_id(i.finding)
        if osv:
            by_osv[osv][i.member_key] = i.finding.severity.value
    edges = [Edge(type="shared-dependency", members=list(reach), key=osv,
                  detail={"reachability": reach})
             for osv, reach in by_osv.items() if len(reach) >= 2]
    return sorted(edges, key=lambda e: e.key)


def write_edges(path: str | Path, edges: list[Edge]) -> None:
    """Write edges to a JSON file (sorted, deterministic)."""
    Path(path).write_text(json.dumps([e.to_dict() for e in edges], indent=2))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_edges.py -v`
Expected: PASS. `uv run ruff check sec_harness/correlate/edges.py tests/test_correlate_edges.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/edges.py skills/sec-harness/helpers/tests/test_correlate_edges.py
git status
git commit -m "feat(correlate): shared-dependency OSV roll-up edge"
```

---

### Task 5: same-class recurrence edge

**Files:**
- Modify: `helpers/sec_harness/correlate/edges.py`
- Test: `helpers/tests/test_correlate_edges.py` (extend)

**Interfaces:**
- Consumes: `IngestedFinding`, `Edge`.
- Produces: `same_class_recurrence_edges(ings) -> list[Edge]` — over findings with status in `{confirmed, needs-deployment-testing, fixed}`, group by a **shape key** = `f.fingerprint or f"{f.cls}:{f.rule_id}"`; emit ONE `type="same-class-recurrence"` edge per shape key present in ≥2 distinct member keys, `key=<shape>`, `detail={"cls": <cls>, "systemic": True}`.

- [ ] **Step 1: Write the failing test (append)**

```python
def test_same_class_recurrence_flags_systemic(tmp_path: Path):
    from sec_harness.correlate.edges import same_class_recurrence_edges

    def _authz(fid, fp):
        return {"id": fid, "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
                "rule_id": "ce-from-payload", "file": "x.go", "line": 1, "message": "m",
                "evidence_sources": ["ast-grep:x"], "fingerprint": fp}

    ma = build_member(tmp_path, slug="a-1", scan_scope=".", findings=[_authz("N-1", "authz|ce|src")])
    mb = build_member(tmp_path, slug="b-1", scan_scope=".", findings=[_authz("N-2", "authz|ce|src")])
    man = Manifest(product="p", members=[Member(**ma), Member(**mb)])
    edges = same_class_recurrence_edges(ingest(man))
    assert len(edges) == 1
    assert edges[0].detail["systemic"] is True
    assert edges[0].detail["cls"] == "authz"
    assert set(edges[0].members) == {"a-1#.", "b-1#."}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_edges.py::test_same_class_recurrence_flags_systemic -v`
Expected: FAIL — `same_class_recurrence_edges` missing.

- [ ] **Step 3: Write minimal implementation (append to edges.py)**

```python
_RECURRENCE_STATUSES = {"confirmed", "needs-deployment-testing", "fixed"}


def same_class_recurrence_edges(ings: list[IngestedFinding]) -> list[Edge]:
    """Flag a shape (fingerprint, else cls:rule_id) recurring across ≥2 members as systemic.

    Args:
        ings: All ingested findings.

    Returns:
        One ``same-class-recurrence`` edge per shape present in ≥2 distinct member keys (only
        findings whose status is confirmed/needs-deployment-testing/fixed count), sorted by key.
    """
    by_shape: dict[str, dict[str, str]] = defaultdict(dict)
    for i in ings:
        if i.finding.status.value not in _RECURRENCE_STATUSES:
            continue
        shape = i.finding.fingerprint or f"{i.finding.cls}:{i.finding.rule_id}"
        by_shape[shape][i.member_key] = i.finding.cls
    edges = [Edge(type="same-class-recurrence", members=list(mk), key=shape,
                  detail={"cls": next(iter(mk.values())), "systemic": True})
             for shape, mk in by_shape.items() if len(mk) >= 2]
    return sorted(edges, key=lambda e: e.key)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_edges.py -v`
Expected: PASS (2). `uv run ruff check sec_harness/correlate/edges.py tests/test_correlate_edges.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/edges.py skills/sec-harness/helpers/tests/test_correlate_edges.py
git status
git commit -m "feat(correlate): same-class recurrence (systemic) edge"
```

---

### Task 6: `correlate` CLI + regression

**Files:**
- Create: `helpers/sec_harness/correlate/cli.py`
- Test: `helpers/tests/test_correlate_cli.py`

**Interfaces:**
- Consumes: `load_manifest`, `CorrelationWorkspace`, `ingest`, `shared_dependency_edges`, `same_class_recurrence_edges`, `write_edges`.
- Produces: `python -m sec_harness.correlate --manifest <product.json> --out <dir>` — loads the manifest, copies it into the workspace, ingests, runs both deterministic joins, writes `edges.json`; prints `{"edges": <n>, "members": <m>}`. `main(argv) -> int`.

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_correlate_cli.py
from __future__ import annotations

import json
from pathlib import Path

from sec_harness.correlate.cli import main
from tests.correlate_fixtures import build_member


def test_cli_writes_edges(tmp_path: Path):
    ma = build_member(tmp_path, slug="a-1", scan_scope=".",
                      findings=[{"id": "C-1", "cls": "deps", "status": "confirmed", "severity": "low",
                                 "rule_id": "osv:GHSA-x", "file": "lock", "line": 1, "message": "m",
                                 "evidence_sources": ["sca:osv:GHSA-x"]}])
    mb = build_member(tmp_path, slug="b-1", scan_scope=".",
                      findings=[{"id": "C-2", "cls": "deps", "status": "confirmed", "severity": "high",
                                 "rule_id": "osv:GHSA-x", "file": "lock", "line": 1, "message": "m",
                                 "evidence_sources": ["sca:osv:GHSA-x"]}])
    manifest = tmp_path / "product.json"
    manifest.write_text(json.dumps({"product": "p", "members": [ma, mb]}))
    out = tmp_path / "corr"
    rc = main(["--manifest", str(manifest), "--out", str(out)])
    assert rc == 0
    edges = json.loads((out / "edges.json").read_text())
    assert any(e["type"] == "shared-dependency" and e["key"] == "GHSA-x" for e in edges)
    assert (out / "product.json").exists()  # manifest copied into the workspace
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_cli.py -v`
Expected: FAIL — `sec_harness.correlate.cli` missing.

- [ ] **Step 3: Write minimal implementation**

```python
# helpers/sec_harness/correlate/cli.py
"""CLI: correlate N per-repo scans of one product into a cross-repo edge graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sec_harness.correlate.edges import (
    same_class_recurrence_edges, shared_dependency_edges, write_edges,
)
from sec_harness.correlate.ingest import ingest
from sec_harness.correlate.manifest import load_manifest
from sec_harness.correlate.workspace import CorrelationWorkspace


def main(argv: list[str] | None = None) -> int:
    """Run the deterministic correlation core (B-Plan 1).

    Args:
        argv: Optional argument vector.

    Returns:
        0 on success.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-correlate")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    cw = CorrelationWorkspace(Path(args.out))
    cw.ensure()
    cw.manifest_path.write_text(Path(args.manifest).read_text())  # copy manifest into the workspace
    ings = ingest(manifest)
    edges = shared_dependency_edges(ings) + same_class_recurrence_edges(ings)
    write_edges(cw.edges_path, edges)
    print(json.dumps({"edges": len(edges), "members": len(manifest.members)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_correlate_cli.py -v`
Expected: PASS. Then full suite `uv run pytest -q` (only the known env-only failures; zero NEW). `uv run ruff check sec_harness/correlate/ tests/test_correlate_*.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/correlate/cli.py skills/sec-harness/helpers/tests/test_correlate_cli.py
git status
git commit -m "feat(correlate): CLI runs ingest + deterministic joins -> edges.json"
```

---

## Self-Review

**1. Spec coverage (B-Plan 1 = Spec B §2 + the two deterministic §3 edges):**
- Manifest + roles (§2) → Task 1. ✓
- CorrelationWorkspace + member key `slug#scan_scope` (§2) → Task 2 + Task 1 `Member.member_key`. ✓
- Read-only ingest + immutability invariant (§1, §2) → Task 3 (byte-compare snapshot test). ✓
- shared-dependency roll-up (§3) → Task 4. ✓
- same-class-recurrence/systemic (§3) → Task 5. ✓
- `edges.json` + CLI (§2, §3) → Task 6. ✓
- **Resequenced to B-Plan 2 (noted):** contract-consistency lattice, control-enforces / trust-boundary-stitch, re-thresholding, adversary, artifacts — all need member-source reads and/or LLM, out of B-Plan 1's deterministic-only scope. Called out in Global Constraints.

**2. Placeholder scan:** No TBD/TODO; every code step is runnable; every test asserts concrete values (incl. the immutability byte-compare).

**3. Type consistency:** `Member.member_key` (`slug#scan_scope`) used identically in Tasks 1/3/4/5; `IngestedFinding` fields (`member_key`/`role`/`cross_repo_id`/`finding`) consistent across ingest + edges; `Edge` (`type`/`members`/`key`/`detail` + `to_dict`) consistent across Tasks 4/5/6; `member_workspace` sidecar path (`<repo_root>/.sec-harness/<slug>`) matches the fixture's `RepoMemory(root=...)` exactly so tests resolve the same sidecar the code does.

**Contract note:** new `correlate` package only; `models.py`/`evidence.py` untouched → no Go-golden regen.
