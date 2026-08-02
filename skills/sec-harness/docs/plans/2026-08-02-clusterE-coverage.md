# Cluster E — Coverage Accounting (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** A "clean scan" / "N findings" must carry a coverage denominator: which languages got dataflow vs pattern-only vs nothing, so a Liquid-majority or 0-candidate repo can't read as fully covered.

**Architecture:** New `coverage.py` computes per-language `{files, tier}` from the profile + which backends ran. `run_prefilter` adds a `coverage` block to its result and persists `kb/coverage.json`. `report.py` renders a "Coverage & limitations" section from it. `partition.must_investigate(profile)` is the tested invariant that investigate runs even at 0 candidates.

**Tech Stack:** Python 3.13 stdlib-only, pytest/ruff/ty. Run from `skills/sec-harness/helpers/`.

## Global Constraints
- stdlib-only; line 100; ruff+ty clean on changed files.
- Coverage is derived deterministically from `profile.languages` + `backends_run` + `profile.sast_plan`.
- Evidence: O-007 (0-candidate business-logic reads clean), O-033 (Liquid 58% uncovered, prefilter said "4 backends ran, 0 failed").
- Branch `skill-audit-driver-20260731`; stage only `skills/` paths; never `git add -A`.

---

### Task 1: coverage.compute_coverage

**Files:** Create `helpers/sec_harness/coverage.py`. Test: `helpers/tests/test_coverage.py`.

**Interfaces:** `compute_coverage(profile, backends_run: list[str], target: str) -> dict` returning
`{"languages": [{"language": str, "files": int, "tier": "dataflow"|"pattern-only"|"none"}, ...], "dataflow_pct": int, "uncovered": [str, ...]}`.

- [ ] **Step 0: verify** how `profile.sast_plan` is accessed (attribute vs dict) — read a ScanProfile: `uv run python -c "from sec_harness.profile import load_profile; p=load_profile('<any kb/scan-profile.json>'); print(type(p.sast_plan), p.languages)"`. Adapt Step 3's access to the real shape (it may be a dict on the object).
- [ ] **Step 1: failing test**:
```python
def test_compute_coverage_tiers(tmp_path):
    from sec_harness.coverage import compute_coverage
    (tmp_path / "a.js").write_text("1")
    (tmp_path / "b.liquid").write_text("1")
    class P:
        languages = ["javascript", "liquid"]
        sast_plan = {"codeql": {"run": True, "languages": ["javascript"]},
                     "semgrep": {"run": True, "rulesets": ["rules/semgrep/javascript"]}}
    cov = compute_coverage(P(), ["semgrep", "codeql"], str(tmp_path))
    by = {l["language"]: l for l in cov["languages"]}
    assert by["javascript"]["tier"] == "dataflow"      # codeql covers it
    assert by["liquid"]["tier"] == "none"              # no codeql pack, no semgrep ruleset
    assert "liquid" in cov["uncovered"]
    assert by["javascript"]["files"] == 1 and by["liquid"]["files"] == 1
```
- [ ] **Step 2: run, expect FAIL** (module missing).
- [ ] **Step 3: implement** `coverage.py`:
```python
"""Per-language SAST coverage accounting: dataflow vs pattern-only vs none (O-007/O-033)."""
from __future__ import annotations

from pathlib import Path

# language -> source extensions (lowercased, no dot). Only languages the harness reasons about.
_LANG_EXT: dict[str, tuple[str, ...]] = {
    "javascript": ("js", "jsx", "mjs", "cjs"), "typescript": ("ts", "tsx"),
    "python": ("py",), "go": ("go",), "java": ("java",), "ruby": ("rb",),
    "php": ("php",), "csharp": ("cs",), "cpp": ("c", "cc", "cpp", "cxx", "h", "hpp"),
    "rust": ("rs",), "swift": ("swift",), "liquid": ("liquid",), "scss": ("scss",),
    "html": ("html", "htm"), "graphql": ("graphql", "gql"),
}
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor",
              ".sec-harness", "__pycache__", "coverage"}


def _count_files(target: str, lang: str) -> int:
    exts = _LANG_EXT.get(lang, ())
    if not exts:
        return 0
    root = Path(target)
    n = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.suffix.lower().lstrip(".") in exts:
            n += 1
    return n


def _semgrep_langs(sast_plan: dict) -> set[str]:
    langs: set[str] = set()
    for rs in ((sast_plan.get("semgrep") or {}).get("rulesets") or []):
        parts = str(rs).rstrip("/").split("/")
        if len(parts) >= 2 and parts[-2] == "semgrep":
            langs.add(parts[-1])
    return langs


def compute_coverage(profile, backends_run: list[str], target: str) -> dict:
    """Per-language coverage tier from the profile + which backends actually ran."""
    sast_plan = getattr(profile, "sast_plan", None) or {}
    codeql_langs = set((sast_plan.get("codeql") or {}).get("languages") or []) \
        if "codeql" in backends_run else set()
    semgrep_langs = _semgrep_langs(sast_plan) if "semgrep" in backends_run else set()
    langs = []
    for lang in (getattr(profile, "languages", []) or []):
        if lang in codeql_langs:
            tier = "dataflow"
        elif lang in semgrep_langs:
            tier = "pattern-only"
        else:
            tier = "none"
        langs.append({"language": lang, "files": _count_files(target, lang), "tier": tier})
    total = sum(l["files"] for l in langs) or 1
    dataflow_files = sum(l["files"] for l in langs if l["tier"] == "dataflow")
    return {
        "languages": langs,
        "dataflow_pct": round(100 * dataflow_files / total),
        "uncovered": [l["language"] for l in langs if l["tier"] == "none" and l["files"] > 0],
    }
```
- [ ] **Step 4: run PASS**; **Step 5: lint** coverage.py + test; **Step 6: commit** — `git commit -m "feat(coverage): per-language dataflow/pattern-only/none accounting (O-033)"` (stage the two paths).

---

### Task 2: prefilter emits + persists coverage

**Files:** Modify `helpers/sec_harness/prefilter.py` (`run_prefilter` return + persist). Test: `helpers/tests/test_prefilter.py` (a light unit — or extend existing).

**Interfaces:** `run_prefilter` result gains `"coverage": <compute_coverage output>`; also writes `ws.kb / "coverage.json"`.

- [ ] **Step 1: failing test** — a focused test that `run_prefilter`'s result has a `coverage` key with a `languages` list and that `kb/coverage.json` is written. (If `run_prefilter` is heavy to invoke in a unit test, instead test the persistence helper directly — see Step 3.)
```python
def test_run_prefilter_result_has_coverage(monkeypatch, tmp_path):
    # if full run_prefilter is too heavy, assert the coverage block is added by calling the
    # small persistence path; otherwise assert result["coverage"]["languages"] is a list.
    ...  # implementer: pick the lightest reliable assertion given run_prefilter's test fixtures
```
- [ ] **Step 2: run FAIL**.
- [ ] **Step 3: implement** — in `run_prefilter`, before the return, compute + persist coverage:
```python
    from sec_harness.coverage import compute_coverage
    coverage = compute_coverage(profile, ran, str(target))
    (ws.kb / "coverage.json").write_text(json.dumps(coverage, indent=2))
```
(ensure `json` is imported; `ws.kb` dir exists — `ws.kb.mkdir(parents=True, exist_ok=True)` if needed) and add `"coverage": coverage,` to the returned dict. `profile` is the function's profile arg; `ran` is the backends_run list; `target` the scanned path.
- [ ] **Step 4: run PASS**; **Step 5: lint**; **Step 6: commit** — `git commit -m "feat(prefilter): emit + persist coverage block (O-007/O-033)"` (stage prefilter.py + test).

---

### Task 3: report renders "Coverage & limitations"

**Files:** Modify `helpers/sec_harness/report.py` (`to_markdown`). Test: `helpers/tests/test_report.py`.

- [ ] **Step 1: failing test** — a report rendered for a workspace whose `kb/coverage.json` marks `liquid` tier `none` contains a "Coverage" section naming liquid as uncovered.
```python
def test_report_renders_coverage_section(tmp_path):
    import json
    from sec_harness.workspace import Workspace
    from sec_harness.report import write_report
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    (ws.kb).mkdir(parents=True, exist_ok=True)
    (ws.kb / "coverage.json").write_text(json.dumps({
        "languages": [{"language": "liquid", "files": 194, "tier": "none"},
                      {"language": "javascript", "files": 40, "tier": "dataflow"}],
        "dataflow_pct": 17, "uncovered": ["liquid"]}))
    write_report(ws)
    md = (ws.reports / "report.md").read_text()
    assert "Coverage" in md and "liquid" in md and "17%" in md
```
- [ ] **Step 2: run FAIL**.
- [ ] **Step 3: implement** — in `to_markdown` (or `write_report`), read `ws.kb / "coverage.json"` if present and append a section:
```python
## Coverage & limitations

_SAST coverage by language. `none` = no mechanical dataflow OR pattern analysis (LLM shape-hunting only)._

| Language | Files | Tier |
|----------|-------|------|
... one row per language ...

Dataflow coverage: {dataflow_pct}% of counted source. Uncovered (LLM-only): {uncovered joined}.
```
Render nothing (or "coverage: not recorded") if the file is absent, so existing report tests are unaffected. Wire `to_markdown` to accept the coverage dict (read it in `write_report` and pass through), or read the file inside `to_markdown` from the workspace — match the existing signature style.
- [ ] **Step 4: run PASS** (+ existing `test_report.py` still green — coverage section only appears when the file exists).
- [ ] **Step 5: lint**; **Step 6: commit** — `git commit -m "feat(report): render Coverage & limitations section (O-033)"` (stage report.py + test).

---

### Task 4: must_investigate invariant

**Files:** Modify `helpers/sec_harness/partition.py` (add `must_investigate`). Test: `helpers/tests/test_partition.py`. Doc: `SKILL.md`.

- [ ] **Step 1: failing test**:
```python
def test_must_investigate_true_when_classes_exist_even_at_zero_candidates():
    from sec_harness.partition import must_investigate
    class P: agents_to_spawn = ["business-logic"]
    class Q: agents_to_spawn = []
    assert must_investigate(P()) is True     # 0 candidates but a hunt-list class exists -> must run
    assert must_investigate(Q()) is False
```
- [ ] **Step 2: run FAIL**.
- [ ] **Step 3: implement** — add to partition.py:
```python
def must_investigate(profile) -> bool:
    """Investigate MUST run when the profile plans any class, EVEN at 0 SAST candidates (O-007).

    A business-logic target is SAST-empty but not risk-free; gating investigate on candidate
    existence is a signal inversion. The hunt list drives investigation regardless of candidates.
    """
    return bool(getattr(profile, "agents_to_spawn", []) or [])
```
- [ ] **Step 4: run PASS**; **Step 5: lint**.
- [ ] **Step 6: SKILL.md** — in Phase 2-3, add: "Investigate runs whenever `must_investigate(profile)` is true (any planned class) — even at 0 SAST candidates. A 0-candidate business-logic repo is a coverage story, not a clean bill (O-007)."
- [ ] **Step 7: commit** — `git commit -m "feat(partition): must_investigate invariant for 0-candidate targets (O-007)"` (stage partition.py + test + SKILL.md).

---

## Self-review
- Spec coverage: GSD Cluster E → Task 1 (compute), 2 (emit/persist), 3 (report), 4 (invariant). ✓
- Non-breaking: coverage section only renders when kb/coverage.json exists; existing report tests unaffected. ✓
- Type consistency: `compute_coverage(profile, list[str], str) -> dict`, `must_investigate(profile) -> bool`. ✓
