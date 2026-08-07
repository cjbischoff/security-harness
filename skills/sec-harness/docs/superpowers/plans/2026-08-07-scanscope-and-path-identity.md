# ScanScope Spine + Path/Identity (Spec A · Plan 1 of 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the harness a single canonical `repo_root` + `scan_scope` (persisted as `kb/scan-scope.json`) that every phase, gate, and discovery step resolves against, fixing all monorepo-subdir path failures and the docs-discovery coverage gap.

**Architecture:** A new stdlib-only `sec_harness/scanscope.py` resolves the git top-level as `repo_root` and the scan target as `scan_scope`, and persists a `ScanScope` to `kb/scan-scope.json` (NOT on the frozen `CampaignState`). `repo_slug`, `discover_context_files`, and `claims_from_markdown` become scope-aware. Downstream gate/dedupe/verify already take a `root` arg — Plan 1 makes the orchestrator pass `scope.repo_root` and documents the token contract; it does not change their signatures.

**Tech Stack:** Python 3 stdlib only (no runtime deps — hard rule); `pytest` via `uv run`; `ruff` (line-length 100) + `ty`. Git via `subprocess` with an injectable `runner` (existing pattern in `repo_memory.repo_slug`).

## Global Constraints

- Core is **stdlib-only**. Do NOT add a runtime dependency to `pyproject.toml`. (verbatim: CLAUDE.md §7)
- **Do NOT modify** `helpers/sec_harness/models.py` or `helpers/sec_harness/evidence.py` — frozen JSON contract mirrored by the Go port (`go/internal/model/testdata`, `TestParity`). Plan 1 touches neither.
- **You touch only `skills/` paths.** Never `git add -A` / `git add .`; stage explicit `skills/sec-harness/...` paths; `git status` must show only skill paths before every commit. Never touch `go/`.
- Work on branch `spec/process-review-hardening-20260807` (already created off `main`). Personal remote → no GPG signing, no AI attribution in commits. Do NOT push (user publishes).
- All work runs from `skills/sec-harness/helpers/`. Tests live in `helpers/tests/`. Run tests with `uv run pytest`.
- Every new module starts with `from __future__ import annotations` and full Google-style docstrings on public functions/classes (CLAUDE.md hard rule).

---

## File Structure

- **Create** `helpers/sec_harness/scanscope.py` — `ScanScope` dataclass + `resolve()` / `write_scope()` / `load_scope()` / `rel_to_root()`. One responsibility: canonical scope resolution + persistence.
- **Create** `helpers/tests/test_scanscope.py` — unit tests for the above.
- **Modify** `helpers/sec_harness/repo_memory.py` — `repo_slug` becomes scope-aware (identity includes scan-scope subpath).
- **Modify** `helpers/tests/test_repo_memory.py` (create if absent) — slug collision tests.
- **Modify** `helpers/sec_harness/context.py` — `discover_context_files` becomes `(repo_root, scan_scope=".")`, globs from repo_root, adds monorepo service-doc roots + `.puml`/`.dot` text diagrams, records image diagrams.
- **Modify** `helpers/tests/test_context.py` (create if absent) — discovery-scope tests.
- **Modify** `helpers/sec_harness/phase_gate.py` — `_MD_CITATION` extension coverage + range support in `claims_from_markdown`.
- **Modify** `helpers/tests/test_phase_gate.py` (create if absent) — citation-extraction tests.
- **Modify** `helpers/sec_harness/cli.py` — write `kb/scan-scope.json` at pass start (scan/begin path).
- **Modify** `skills/sec-harness/SKILL.md` + `skills/sec-harness/references/prompt-constants.md` — document `{{REPO_ROOT}}`/`{{SCAN_SCOPE}}` tokens + the "resolve against repo_root" invariant.

---

### Task 1: `scanscope.py` — resolve + persist canonical scope

**Files:**
- Create: `helpers/sec_harness/scanscope.py`
- Test: `helpers/tests/test_scanscope.py`

**Interfaces:**
- Produces:
  - `@dataclass ScanScope(repo_root: str, scan_scope: str, path_base: str = "repo-root", slug: str = "", sha: str = "", doc_roots: list[str] = [])` with `to_dict()`/`from_dict(d)`.
  - `resolve(target: str | Path, *, sha: str = "", runner=subprocess.run) -> ScanScope`
  - `write_scope(ws, scope: ScanScope) -> Path` (writes `ws.kb/"scan-scope.json"`)
  - `load_scope(ws) -> ScanScope | None`
  - `rel_to_root(path: str | Path, scope: ScanScope) -> str` (returns a repo-root-relative POSIX string)

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_scanscope.py
from __future__ import annotations

import subprocess
from pathlib import Path

from sec_harness.scanscope import ScanScope, resolve, write_scope, load_scope, rel_to_root
from sec_harness.workspace import Workspace


def _fake_git(toplevel: str):
    def runner(cmd, capture_output=True, text=True, check=False):  # noqa: ARG001
        class R:
            returncode = 0
            stdout = toplevel + "\n"
            stderr = ""
        return R()
    return runner


def test_resolve_monorepo_subdir(tmp_path: Path):
    repo = tmp_path / "monorepo"
    (repo / "internal" / "svc").mkdir(parents=True)
    scope = resolve(repo / "internal" / "svc", sha="abc123",
                    runner=_fake_git(str(repo)))
    assert scope.repo_root == str(repo)
    assert scope.scan_scope == "internal/svc"
    assert scope.path_base == "repo-root"
    assert scope.sha == "abc123"


def test_resolve_whole_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    scope = resolve(repo, runner=_fake_git(str(repo)))
    assert scope.scan_scope == "."


def test_resolve_non_git_falls_back_to_target(tmp_path: Path):
    d = tmp_path / "plain"
    d.mkdir()

    def failing(cmd, capture_output=True, text=True, check=False):  # noqa: ARG001
        class R:
            returncode = 128
            stdout = ""
            stderr = "not a git repo"
        return R()

    scope = resolve(d, runner=failing)
    assert scope.repo_root == str(d.resolve())
    assert scope.scan_scope == "."


def test_write_and_load_roundtrip(tmp_path: Path):
    ws = Workspace(tmp_path / "ws")
    ws.ensure()
    scope = ScanScope(repo_root=str(tmp_path), scan_scope="internal/svc",
                      slug="repo-1a2b3c4d", sha="deadbeef",
                      doc_roots=["internal/svc", "docs/services/svc"])
    p = write_scope(ws, scope)
    assert p == ws.kb / "scan-scope.json"
    loaded = load_scope(ws)
    assert loaded == scope


def test_load_missing_returns_none(tmp_path: Path):
    ws = Workspace(tmp_path / "ws")
    ws.ensure()
    assert load_scope(ws) is None


def test_rel_to_root_absolute_and_subdir(tmp_path: Path):
    scope = ScanScope(repo_root=str(tmp_path), scan_scope="internal/svc")
    # absolute path under repo_root -> repo-root-relative
    assert rel_to_root(tmp_path / "internal/svc/a.go", scope) == "internal/svc/a.go"
    # scan-scope-relative path -> repo-root-relative
    assert rel_to_root("a.go", scope) == "internal/svc/a.go"
    # already repo-root-relative -> unchanged
    assert rel_to_root("internal/svc/a.go", scope) == "internal/svc/a.go"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_scanscope.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'sec_harness.scanscope'`.

- [ ] **Step 3: Write minimal implementation**

```python
# helpers/sec_harness/scanscope.py
"""Canonical scan scope: the one repo_root + scan_scope every phase resolves against.

A single scan targets either a whole repo or a sub-path of a monorepo. Historically each
phase/gate/dedupe/verify resolved paths against whatever base its caller happened to pass,
so a monorepo sub-service scan (target = ``internal/svc``) broke: recon cited repo-root-
relative refs, the architecture agent cited subdir-relative refs, and gates guessed a base
per phase. ``ScanScope`` fixes the base once — ``repo_root`` is the git top-level, ``scan_scope``
is the target relative to it — and persists it to ``kb/scan-scope.json`` (NOT the frozen
``CampaignState``). Everything resolves against ``repo_root``; agents cite repo-root-relative.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanScope:
    """The canonical resolution base for one scan.

    Attributes:
        repo_root: Absolute path to the git top-level (or the target if not a git repo).
        scan_scope: Target path relative to ``repo_root`` ("." for a whole-repo scan).
        path_base: Always ``"repo-root"`` — the declared base all refs resolve against.
        slug: Stable per-scan identity slug (see :func:`sec_harness.repo_memory.repo_slug`).
        sha: Pinned git SHA for the pass (informational).
        doc_roots: Repo-root-relative dirs to search for context docs (scan scope + any
            canonical monorepo service-doc locations for this service).
    """

    repo_root: str
    scan_scope: str
    path_base: str = "repo-root"
    slug: str = ""
    sha: str = ""
    doc_roots: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict of this scope."""
        return {
            "repo_root": self.repo_root, "scan_scope": self.scan_scope,
            "path_base": self.path_base, "slug": self.slug, "sha": self.sha,
            "doc_roots": list(self.doc_roots),
        }

    @classmethod
    def from_dict(cls, d: dict) -> ScanScope:
        """Rebuild a :class:`ScanScope` from :meth:`to_dict` output."""
        return cls(
            repo_root=d["repo_root"], scan_scope=d.get("scan_scope", "."),
            path_base=d.get("path_base", "repo-root"), slug=d.get("slug", ""),
            sha=d.get("sha", ""), doc_roots=list(d.get("doc_roots", [])),
        )


def _git_toplevel(target: Path, runner) -> Path | None:
    """Return the git top-level containing ``target``, or None if not a git repo."""
    try:
        res = runner(["git", "-C", str(target), "rev-parse", "--show-toplevel"],
                     capture_output=True, text=True, check=False)
    except OSError:
        return None
    out = (res.stdout or "").strip()
    if res.returncode == 0 and out:
        return Path(out)
    return None


def _service_doc_roots(repo_root: Path, scan_scope: str) -> list[str]:
    """Canonical monorepo doc dirs for a sub-service, when they exist under ``repo_root``.

    A monorepo often stores a service's docs at the repo root (``docs/services/<svc>``,
    ``docs/global-services/<svc>``) rather than inside the service subdir. Include those so
    discovery does not miss them on a sub-service scan.
    """
    if scan_scope == ".":
        return []
    svc = Path(scan_scope).name
    candidates = [f"docs/services/{svc}", f"docs/global-services/{svc}", f"docs/{svc}"]
    return [c for c in candidates if (repo_root / c).is_dir()]


def resolve(target: str | Path, *, sha: str = "", runner=subprocess.run) -> ScanScope:
    """Resolve the canonical :class:`ScanScope` for a scan target.

    Args:
        target: Path being scanned (repo root or a monorepo sub-path).
        sha: Pinned git SHA for the pass (informational).
        runner: Injectable subprocess runner (for tests).

    Returns:
        A :class:`ScanScope` with ``repo_root`` = git top-level (or the resolved target if
        not a git repo), ``scan_scope`` = target relative to ``repo_root`` ("." if equal),
        and ``doc_roots`` seeded with the scan scope + any canonical service-doc dirs.
    """
    target = Path(target).expanduser().resolve()
    top = _git_toplevel(target, runner)
    repo_root = (top.resolve() if top else target)
    try:
        rel = target.relative_to(repo_root).as_posix()
    except ValueError:
        rel = "."
    scan_scope = rel or "."
    doc_roots = ([] if scan_scope == "." else [scan_scope]) + \
        _service_doc_roots(repo_root, scan_scope)
    return ScanScope(repo_root=str(repo_root), scan_scope=scan_scope, sha=sha,
                     doc_roots=doc_roots)


def write_scope(ws, scope: ScanScope) -> Path:
    """Persist ``scope`` to ``ws.kb/scan-scope.json`` and return the path."""
    ws.kb.mkdir(parents=True, exist_ok=True)
    p = ws.kb / "scan-scope.json"
    p.write_text(json.dumps(scope.to_dict(), indent=2))
    return p


def load_scope(ws) -> ScanScope | None:
    """Load ``ws.kb/scan-scope.json`` or ``None`` if absent."""
    p = ws.kb / "scan-scope.json"
    return ScanScope.from_dict(json.loads(p.read_text())) if p.exists() else None


def rel_to_root(path: str | Path, scope: ScanScope) -> str:
    """Normalize ``path`` to a repo-root-relative POSIX string using ``scope``.

    Accepts an absolute path under ``repo_root``, a path already relative to ``repo_root``,
    or a path relative to ``scan_scope`` (the common agent shorthand). Anything that cannot
    be made repo-root-relative is returned as a POSIX string unchanged.
    """
    root = Path(scope.repo_root)
    p = Path(path)
    if p.is_absolute():
        try:
            return p.relative_to(root).as_posix()
        except ValueError:
            return p.as_posix()
    # already repo-root-relative?
    if (root / p).exists():
        return p.as_posix()
    # scan-scope-relative?
    if scope.scan_scope != "." and (root / scope.scan_scope / p).exists():
        return (Path(scope.scan_scope) / p).as_posix()
    # default: assume scan-scope-relative when scoped, else as-is
    if scope.scan_scope != ".":
        return (Path(scope.scan_scope) / p).as_posix()
    return p.as_posix()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_scanscope.py -v`
Expected: PASS (6 tests). Then `uv run ruff check sec_harness/scanscope.py tests/test_scanscope.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/scanscope.py skills/sec-harness/helpers/tests/test_scanscope.py
git status   # confirm ONLY these two skill paths
git commit -m "feat(scanscope): canonical repo_root + scan_scope resolution and persistence"
```

---

### Task 2: `repo_slug` scope-aware identity (fix monorepo collision)

**Files:**
- Modify: `helpers/sec_harness/repo_memory.py:67-96` (`repo_slug`)
- Test: `helpers/tests/test_repo_memory.py` (create if absent)

**Interfaces:**
- Consumes: nothing new (keeps the `(target, *, runner=subprocess.run)` signature).
- Produces: `repo_slug` whose identity string includes the scan-scope subpath, so two subdirs of one monorepo (same `origin`) get **different** slugs. Standalone-repo slugs are unchanged.

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_repo_memory.py
from __future__ import annotations

from pathlib import Path

from sec_harness.repo_memory import repo_slug


def _origin(url: str):
    def runner(cmd, capture_output=True, text=True, check=False):  # noqa: ARG001
        class R:
            returncode = 0
            stdout = url + "\n"
            stderr = ""
        return R()
    return runner


def test_monorepo_subdirs_get_distinct_slugs(tmp_path: Path):
    repo = tmp_path / "mono"
    (repo / "internal" / "svcA").mkdir(parents=True)
    (repo / "internal" / "svcB").mkdir(parents=True)
    url = "git@github.com:org/mono.git"
    a = repo_slug(repo / "internal" / "svcA", runner=_origin(url))
    b = repo_slug(repo / "internal" / "svcB", runner=_origin(url))
    assert a != b, "monorepo sub-services must not collide"


def test_whole_repo_slug_stable(tmp_path: Path):
    repo = tmp_path / "solo"
    repo.mkdir()
    url = "git@github.com:org/solo.git"
    s1 = repo_slug(repo, runner=_origin(url))
    s2 = repo_slug(repo, runner=_origin(url))
    assert s1 == s2
    assert s1.startswith("solo-")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_repo_memory.py -v`
Expected: FAIL on `test_monorepo_subdirs_get_distinct_slugs` (both slugs currently equal — identity is the shared origin URL only).

- [ ] **Step 3: Write minimal implementation**

Modify `repo_memory.py` `repo_slug` so the identity string appended-to-hash includes the target's path *relative to the git top-level* when inside a repo. Replace the body's identity derivation:

```python
def repo_slug(target: str | Path, *, runner=subprocess.run) -> str:
    """Derive a stable, filesystem-safe slug identifying a scan target.

    Prefers the git ``origin`` remote URL (stable across clone locations); falls back to the
    absolute path. For a monorepo sub-service the identity also includes the target's path
    relative to the git top-level, so two sub-services of one repo never collide. A short
    hash of the identity is appended.

    Args:
        target: Path to the scan target.
        runner: Injectable subprocess runner (for testing).

    Returns:
        A slug like ``svca-1a2b3c4d`` (monorepo sub-service) or ``myrepo-1a2b3c4d``.
    """
    target = Path(target)
    identity = str(target.resolve())
    name = target.name
    try:
        res = runner(["git", "-C", str(target), "remote", "get-url", "origin"],
                     capture_output=True, text=True, check=False)
        url = (res.stdout or "").strip()
        if res.returncode == 0 and url:
            top = runner(["git", "-C", str(target), "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=False)
            toplevel = (top.stdout or "").strip()
            subpath = ""
            if top.returncode == 0 and toplevel:
                try:
                    subpath = target.resolve().relative_to(Path(toplevel).resolve()).as_posix()
                except ValueError:
                    subpath = ""
            identity = url + ("#" + subpath if subpath and subpath != "." else "")
            base_src = subpath.rsplit("/", 1)[-1] if subpath and subpath != "." else \
                re.sub(r"\.git$", "", url.rstrip("/").rsplit("/", 1)[-1])
            name = base_src or name
    except OSError:
        pass
    base = _SLUG_RE.sub("-", name.lower()).strip("-") or "repo"
    digest = hashlib.sha256(identity.encode()).hexdigest()[:8]
    return f"{base}-{digest}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_repo_memory.py -v`
Expected: PASS. Also run the full suite to catch slug-dependent tests: `uv run pytest -q` (the 3 known env-only failures from CLAUDE.md §2 are acceptable; no NEW failures). `uv run ruff check sec_harness/repo_memory.py tests/test_repo_memory.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/repo_memory.py skills/sec-harness/helpers/tests/test_repo_memory.py
git status
git commit -m "fix(repo_slug): include monorepo subpath in identity so sub-services don't collide"
```

---

### Task 3: Persist scan-scope at pass start (CLI wiring)

**Files:**
- Modify: `helpers/sec_harness/cli.py` (the `scan` subcommand + any `begin`/memory-resolve path that pins a SHA)
- Test: `helpers/tests/test_scanscope_cli.py`

**Interfaces:**
- Consumes: `scanscope.resolve`, `scanscope.write_scope` (Task 1); `repo_slug` (Task 2).
- Produces: after a scan/begin runs, `load_scope(ws)` returns a populated `ScanScope` whose `slug` matches `repo_slug(target)`.

- [ ] **Step 1: Read the CLI to find the pass-start seam**

Run: `cd skills/sec-harness/helpers && uv run python -c "import inspect,sec_harness.cli as c; print(inspect.getsource(c))" | sed -n '1,80p'`
Identify where `--target`/`--workspace`/`--sha` are known and `begin_pass`/`run_scan` is called. The scope write goes immediately after the workspace is resolved and the SHA known.

- [ ] **Step 2: Write the failing test**

```python
# helpers/tests/test_scanscope_cli.py
from __future__ import annotations

from pathlib import Path

from sec_harness.scanscope import load_scope
from sec_harness.workspace import Workspace
from sec_harness.cli import write_scan_scope  # new thin helper added in Step 4


def _fake_git(top: str, origin: str):
    def runner(cmd, capture_output=True, text=True, check=False):  # noqa: ARG001
        class R:
            returncode = 0
            stderr = ""
            stdout = (top if "show-toplevel" in cmd else origin) + "\n"
        return R()
    return runner


def test_write_scan_scope_persists(tmp_path: Path):
    repo = tmp_path / "mono"
    (repo / "internal" / "svc").mkdir(parents=True)
    ws = Workspace(tmp_path / "ws")
    ws.ensure()
    write_scan_scope(ws, repo / "internal" / "svc", sha="cafe",
                     runner=_fake_git(str(repo), "git@github.com:org/mono.git"))
    scope = load_scope(ws)
    assert scope is not None
    assert scope.scan_scope == "internal/svc"
    assert scope.sha == "cafe"
    assert scope.slug.startswith("svc-")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_scanscope_cli.py -v`
Expected: FAIL with `ImportError: cannot import name 'write_scan_scope'`.

- [ ] **Step 4: Write minimal implementation**

Add a thin helper to `cli.py` and call it at pass start:

```python
# in cli.py — imports
from sec_harness.scanscope import resolve as _resolve_scope, write_scope
from sec_harness.repo_memory import repo_slug


def write_scan_scope(ws, target, *, sha: str = "", runner=None):
    """Resolve + persist the canonical ScanScope for a scan (called at pass start).

    Args:
        ws: Campaign workspace.
        target: The scan target path.
        sha: Pinned git SHA for the pass.
        runner: Injectable subprocess runner (tests); defaults to subprocess.run.

    Returns:
        The persisted :class:`sec_harness.scanscope.ScanScope`.
    """
    import subprocess
    r = runner or subprocess.run
    scope = _resolve_scope(target, sha=sha, runner=r)
    scope.slug = repo_slug(target, runner=r)
    write_scope(ws, scope)
    return scope
```

Then, in the `scan` subcommand handler, immediately after the workspace is resolved and the SHA is known (and after `begin_pass`), add:

```python
    write_scan_scope(ws, args.target, sha=sha)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_scanscope_cli.py -v`
Expected: PASS. `uv run ruff check sec_harness/cli.py tests/test_scanscope_cli.py && uv run ty check` — clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/cli.py skills/sec-harness/helpers/tests/test_scanscope_cli.py
git status
git commit -m "feat(cli): persist kb/scan-scope.json at pass start"
```

---

### Task 4: Scope-aware `discover_context_files` (fix docs coverage gap)

**Files:**
- Modify: `helpers/sec_harness/context.py:30-38,93-109`
- Test: `helpers/tests/test_context.py` (create if absent)

**Interfaces:**
- Consumes: `ScanScope.doc_roots` convention (Task 1) — caller passes `repo_root` + `scan_scope`.
- Produces: `discover_context_files(repo_root, scan_scope=".") -> list[str]` — globs from `repo_root`, includes canonical monorepo service-doc roots, ingests `.puml`/`.dot` text diagrams, and returns image-diagram paths (`.png`/`.svg`) so callers can record them as coverage. Back-compat: a single positional arg still works (whole-repo scan).

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_context.py
from __future__ import annotations

from pathlib import Path

from sec_harness.context import discover_context_files


def test_finds_monorepo_root_service_docs_from_subdir(tmp_path: Path):
    repo = tmp_path / "mono"
    (repo / "internal" / "svc").mkdir(parents=True)
    (repo / "internal" / "svc" / "README.md").write_text("svc readme")
    svc_docs = repo / "docs" / "services" / "svc"
    svc_docs.mkdir(parents=True)
    (svc_docs / "data-flow.md").write_text("# data flow")
    found = discover_context_files(repo, "internal/svc")
    assert "internal/svc/README.md" in found
    assert "docs/services/svc/data-flow.md" in found  # was MISSED before


def test_ingests_puml_text_diagrams(tmp_path: Path):
    repo = tmp_path / "repo"
    d = repo / "docs" / "service-story" / "DataFlowDiagrams"
    d.mkdir(parents=True)
    (d / "flow.puml").write_text("@startuml\n@enduml")
    (d / "flow.puml.png").write_bytes(b"\x89PNG")
    found = discover_context_files(repo)
    assert "docs/service-story/DataFlowDiagrams/flow.puml" in found


def test_backcompat_single_arg_whole_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "a.md").write_text("x")
    found = discover_context_files(repo)
    assert "docs/a.md" in found
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_context.py -v`
Expected: FAIL — `test_finds_monorepo_root_service_docs_from_subdir` (root docs missed) and `test_ingests_puml_text_diagrams` (`.puml` not globbed).

- [ ] **Step 3: Write minimal implementation**

In `context.py`, add text-diagram globs and make discovery scope-aware:

```python
# add near _CONTEXT_GLOBS
_DIAGRAM_TEXT_GLOBS = ("**/*.puml", "**/*.dot", "**/*.mmd")
_DIAGRAM_IMAGE_GLOBS = ("**/*.puml.png", "**/*.puml.svg", "**/*.drawio.png")


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
    # canonical monorepo service-doc dirs for a sub-service scan
    if scan_scope != ".":
        svc = Path(scan_scope).name
        for base in (f"docs/services/{svc}", f"docs/global-services/{svc}", f"docs/{svc}"):
            for p in (root / base).glob("**/*.md"):
                if p.is_file():
                    found.add(p.relative_to(root).as_posix())
    return sorted(found)[:_MAX_FILES]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_context.py -v`
Expected: PASS (3 tests). Update `agents/context-ingest.md` (Step 4b below). `uv run ruff check sec_harness/context.py tests/test_context.py && uv run ty check` — clean.

- [ ] **Step 4b: Update the context-ingest agent prompt**

In `skills/sec-harness/agents/context-ingest.md`, the `discover_context_files` invocation line must pass repo_root + scan_scope. Replace the discovery command so it reads scope from `kb/scan-scope.json`:

```
Candidate context files: run (from {{HELPERS_DIR}}):
  uv run python -c "from sec_harness.scanscope import load_scope; from sec_harness.workspace import Workspace; from sec_harness.context import discover_context_files as d; import json; s=load_scope(Workspace('{{WORKSPACE}}')); print(chr(10).join(d(s.repo_root, s.scan_scope)))"
```
Add a line: "Plain-text diagrams (`.puml`/`.dot`) ARE context — read them. Image diagrams (`.puml.png`/`.svg`) cannot be read as text; record each as a `source_pointer` coverage item noting it was not machine-read."

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/context.py skills/sec-harness/helpers/tests/test_context.py skills/sec-harness/agents/context-ingest.md
git status
git commit -m "fix(context): scope-aware discovery — monorepo root docs + puml/dot diagrams"
```

---

### Task 5: `claims_from_markdown` extension + range coverage

**Files:**
- Modify: `helpers/sec_harness/phase_gate.py:256-258` (`_MD_CITATION`)
- Test: `helpers/tests/test_phase_gate.py` (create if absent)

**Interfaces:**
- Consumes: nothing new.
- Produces: `claims_from_markdown` also extracts citations for IaC/config extensions (`yaml`, `yml`, `tf`, `hcl`, `tpl`, `json`, `sh`, `puml`) and line ranges (`file:150-159`), and unwraps single-backtick spans.

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_phase_gate.py
from __future__ import annotations

from sec_harness.phase_gate import claims_from_markdown


def test_extracts_terraform_range_citation():
    claims = claims_from_markdown("The role at `infra/azure/main.tf:150-159` is over-scoped.")
    refs = [r for c in claims for r in c["refs"]]
    assert "infra/azure/main.tf:150" in refs  # range anchors on start line


def test_extracts_yaml_citation():
    claims = claims_from_markdown("DB_SSLMODE=disable at charts/x/responder.yaml:132")
    refs = [r for c in claims for r in c["refs"]]
    assert "charts/x/responder.yaml:132" in refs


def test_still_extracts_go_citation():
    claims = claims_from_markdown("`internal/svc/events.go:39` reads Envelope.Source")
    refs = [r for c in claims for r in c["refs"]]
    assert "internal/svc/events.go:39" in refs
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_phase_gate.py -v`
Expected: FAIL on the terraform + yaml tests (extensions not in the pattern; range not captured).

- [ ] **Step 3: Write minimal implementation**

Replace `_MD_CITATION` in `phase_gate.py`:

```python
_MD_CITATION = re.compile(
    r"([\w./-]+\.(?:py|js|ts|tsx|jsx|go|java|rb|php|c|cc|cpp|rs|"
    r"yaml|yml|tf|hcl|tpl|json|sh|puml|dot)):(\d+(?:-\d+)?)"
)
```

Update `claims_from_markdown` to anchor a range on its start line (reuse `_parse_ref`):

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_phase_gate.py -v`
Expected: PASS (3 tests). Run any existing phase-gate tests too: `uv run pytest -k phase_gate -q`. `uv run ruff check sec_harness/phase_gate.py tests/test_phase_gate.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/phase_gate.py skills/sec-harness/helpers/tests/test_phase_gate.py
git status
git commit -m "fix(phase_gate): extract IaC/config/diagram + range citations from markdown"
```

---

### Task 6: Document the `{{REPO_ROOT}}` / `{{SCAN_SCOPE}}` token contract + resolve-against-repo_root invariant

**Files:**
- Modify: `skills/sec-harness/SKILL.md` (token list in "Running a full audit"; per-phase resolution note)
- Modify: `skills/sec-harness/references/prompt-constants.md` (add the path-base rule to a shared block)
- Test: `helpers/tests/test_docs_invariants.py` (a lightweight doc-contract test)

**Interfaces:**
- Consumes: `kb/scan-scope.json` (Task 3).
- Produces: a documented, testable contract that every agent cites repo-root-relative and every gate resolves against `scope.repo_root`.

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_docs_invariants.py
from __future__ import annotations

from pathlib import Path

_SKILL = Path(__file__).resolve().parents[2] / "SKILL.md"
_CONSTS = Path(__file__).resolve().parents[2] / "references" / "prompt-constants.md"


def test_skill_documents_scope_tokens():
    txt = _SKILL.read_text()
    assert "{{REPO_ROOT}}" in txt
    assert "{{SCAN_SCOPE}}" in txt


def test_prompt_constants_states_repo_root_invariant():
    txt = _CONSTS.read_text().lower()
    assert "repo-root-relative" in txt
    assert "repo_root" in txt
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_docs_invariants.py -v`
Expected: FAIL (tokens/invariant not yet documented).

- [ ] **Step 3: Write minimal implementation**

In `SKILL.md`, in the "Running a full audit" token-substitution list, add `{{REPO_ROOT}}` (absolute git top-level from `kb/scan-scope.json`) and `{{SCAN_SCOPE}}` (target relative to repo_root) alongside the existing `{{TARGET}}`/`{{WORKSPACE}}` tokens, with one sentence: "All agents cite paths **repo-root-relative**; all gates/dedupe/verify resolve against `{{REPO_ROOT}}` (read from `kb/scan-scope.json`)."

In `references/prompt-constants.md`, add to the shared envelope block a `PATH_BASE` rule (verbatim):
"PATH BASE: cite every file reference repo-root-relative (relative to `{{REPO_ROOT}}`), never scan-scope-relative and never a bare basename. A `file:line` you cite must resolve from the repo root."

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_docs_invariants.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/SKILL.md skills/sec-harness/references/prompt-constants.md skills/sec-harness/helpers/tests/test_docs_invariants.py
git status
git commit -m "docs(scanscope): document REPO_ROOT/SCAN_SCOPE tokens + repo-root path invariant"
```

---

### Task 7: Full-suite regression + wiring check

**Files:**
- Test: run the whole suite; no new source.

- [ ] **Step 1: Run the full suite**

Run: `cd skills/sec-harness/helpers && uv run pytest -q`
Expected: only the 3 known env-only failures (missing semgrep submodule / gitignored bench corpus, per CLAUDE.md §2). Zero NEW failures. If a slug-dependent or path-dependent test broke, fix it to consume `ScanScope`/the new `repo_slug` (do not weaken the invariant).

- [ ] **Step 2: Lint + types clean**

Run: `cd skills/sec-harness/helpers && uv run ruff check sec_harness/ tests/ && uv run ty check`
Expected: clean.

- [ ] **Step 3: Commit any test fixups**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/tests/<any-fixed-test>.py
git status
git commit -m "test: adapt path/slug-dependent tests to ScanScope"
```

---

## Self-Review

**1. Spec coverage (Plan 1 = Spec A §3.1 + Theme 1):**
- Canonical `repo_root`/`scan_scope` state → Task 1 (`scanscope.py` + `kb/scan-scope.json`) + Task 3 (persisted at pass start). ✓
- `repo_slug` monorepo collision → Task 2. ✓
- Discovery scope off repo-root + monorepo service docs + `.puml` diagrams → Task 4. ✓
- `claims_from_markdown` backtick/range/extension → Task 5. ✓
- Finding `file` base consistency → `rel_to_root` (Task 1) is the normalizer; wiring it into the write path is a Plan 2 concern (findings are produced in the scoring/gate work) — noted, not silently dropped.
- Resolve-against-repo_root invariant + agent token contract → Task 6. Gate/dedupe/verify **call sites** already accept a `root` arg; Plan 1 documents the invariant and leaves the orchestrator to pass `scope.repo_root` (SKILL.md, Task 6). No signature changes needed.

**2. Placeholder scan:** No TBD/TODO; every code step has runnable code; every test asserts a concrete value.

**3. Type consistency:** `ScanScope` field names (`repo_root`, `scan_scope`, `path_base`, `slug`, `sha`, `doc_roots`) are identical across Tasks 1/3/4; `resolve()`/`write_scope()`/`load_scope()`/`rel_to_root()` signatures match their call sites; `discover_context_files(repo_root, scan_scope=".")` matches its Task 4b agent-prompt invocation and Task 1's `doc_roots` intent.

**Deferred to Plan 2/3 (explicit):** wiring `rel_to_root` into finding-write normalization (Plan 2, where findings are scored/gated); making gate/dedupe/verify orchestration pass `scope.repo_root` in the SKILL.md phase-by-phase driver text (documented here, exercised in Plans 2/3).
