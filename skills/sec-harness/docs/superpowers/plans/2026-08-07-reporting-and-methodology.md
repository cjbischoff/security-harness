# Reporting Completeness + Methodology Knobs (Spec A · Plan 3 of 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a scan's completeness machine-enforced (a class with no confirmed/NDT finding and no logged hole blocks `completeness=="complete"`), surface `needs-deployment-testing` findings in `findings.json`, and expose process-methodology knobs (`adversary_depth`, `model_tier_map`, wave sizing, token budget) as first-class config plus a SKILL.md playbook.

**Architecture:** A new `coverage_ledger.build_coverage_ledger(ws)` derives surfaces from `attack_surface × finding status` and writes `kb/coverage-ledger.json`; `write_report` builds it when absent so the ledger's existing validate/render always fires. `write_report` adds NDT findings to `findings.json` (each carrying its status). `ScanProfile` gains a non-frozen `scan_options` dict (validated, schema-documented) the orchestrator reads. SKILL.md documents the judgement rules.

**Tech Stack:** Python 3 stdlib only; `pytest` via `uv run`; `ruff` (line-length 100) + `ty`.

## Global Constraints

- Core is **stdlib-only**. Add NO runtime dependency to `pyproject.toml`.
- **Do NOT modify** `helpers/sec_harness/models.py` or `helpers/sec_harness/evidence.py` (frozen contract). Plan 3 touches neither. `ScanProfile` (`profile.py`) is NOT frozen — extending it is allowed. **No Go-golden regen required.**
- **You touch only `skills/` paths.** Never `git add -A`; stage explicit `skills/sec-harness/...` paths; `git status` must show only skill paths before every commit. Never touch `go/`.
- Work on branch `spec/reporting-methodology-20260807` (create off `main`). Personal remote → no GPG signing, no AI attribution. Do NOT push.
- Run from `skills/sec-harness/helpers/`. Tests in `helpers/tests/`. `uv run pytest`.
- Preserve the invariant: **"gaps logged, never silently dropped"** — a scan may not read as clean while an attack-surface class is uncovered.
- **`adversary_depth` never bypasses the tool-receipt confirmation bar** — `gate-by-exception` filters *what enters* the FP ladder; it never lets a finding reach `confirmed` without a mechanical receipt. **Model-family diversity stays a hard invariant, not a knob.**

## Already-verified-present (do NOT re-implement)

- `coverage_ledger.validate_coverage_ledger` + `render_markdown` exist and enforce the `complete` invariant (`coverage_ledger.py:16-79`). Plan 3 adds the *builder* + wires enforcement.
- `report.to_markdown` already renders the NDT section (`report.py:152-169`) and the coverage-ledger section when the file is present (`report.py:184-185, 229-230`). Plan 3 makes the ledger get written and adds NDT to `findings.json`.
- `ScanProfile.budget_hint` exists; `discovery_ledger` already has `k`/`max_waves` constants. `scan_options` is the new typed home for the depth/tier/budget knobs the orchestrator reads.

---

## File Structure

- **Modify** `helpers/sec_harness/coverage_ledger.py` — add `build_coverage_ledger(ws) -> dict` (reads `kb/scan-profile.json` + findings; writes `kb/coverage-ledger.json`).
- **Modify** `helpers/sec_harness/report.py` — `write_report` builds the ledger when absent; `findings.json` includes NDT findings.
- **Modify** `helpers/sec_harness/profile.py` — add `scan_options: dict` field + validate it.
- **Modify** `helpers/sec_harness/tests/` — `test_coverage_ledger.py`, `test_report.py`, `test_profile.py` (create/extend).
- **Modify** `references/scan-profile.schema.json` — document `scan_options`.
- **Modify** `skills/sec-harness/SKILL.md` — methodology playbook (depth / model-tier / wave / budget / family-diversity).

---

### Task 1: `build_coverage_ledger` — populate the ledger from attack_surface × findings

**Files:**
- Modify: `helpers/sec_harness/coverage_ledger.py`
- Test: `helpers/tests/test_coverage_ledger.py` (create if absent)

**Interfaces:**
- Consumes: `kb/scan-profile.json` (`attack_surface`, minus `deps`), `read_findings(ws)`, `FindingStatus`.
- Produces: `build_coverage_ledger(ws) -> dict` — one surface per non-`deps` `attack_surface` class: `disposition="reported"` if the class has ≥1 `CONFIRMED`/`FIXED`/`NEEDS_DEPLOYMENT_TESTING` finding; `"no_issue_found"` if it has only `REJECTED`/`INFORMATIONAL` findings; `"needs_follow_up"` if it has NO finding at all. `completeness="complete"` iff no surface is `needs_follow_up` (else `"partial"`; `"unknown"` if there is no profile). Writes `kb/coverage-ledger.json` and returns the dict. Never raises on a missing profile (returns an `unknown` ledger).

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_coverage_ledger.py
from __future__ import annotations

import json
from pathlib import Path

from sec_harness.coverage_ledger import build_coverage_ledger, validate_coverage_ledger
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, write_findings


def _f(cls: str, status: FindingStatus, fid: str) -> Finding:
    return Finding(id=fid, rule_id="r", cls=cls, status=status, severity=Severity.MEDIUM,
                   file="a.py", line=1, message="m", evidence_sources=["semgrep:x"])


def _profile(ws: Workspace, attack_surface: list[str]) -> None:
    (ws.kb).mkdir(parents=True, exist_ok=True)
    (ws.kb / "scan-profile.json").write_text(json.dumps({
        "languages": ["go"], "frameworks": [], "entrypoints": [], "runnable": False,
        "attack_surface": attack_surface, "sast_plan": {}, "agents_to_spawn": attack_surface,
        "budget_hint": {},
    }))


def test_uncovered_class_blocks_complete(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    _profile(ws, ["authz", "sqli"])
    write_findings(ws, [_f("authz", FindingStatus.CONFIRMED, "A-1")])  # sqli has NO finding
    led = build_coverage_ledger(ws)
    disp = {s["id"]: s["disposition"] for s in led["surfaces"]}
    assert disp["authz"] == "reported"
    assert disp["sqli"] == "needs_follow_up"
    assert led["completeness"] == "partial"
    assert validate_coverage_ledger(led) == []  # partial+needs_follow_up is valid
    # persisted
    assert json.loads((ws.kb / "coverage-ledger.json").read_text())["completeness"] == "partial"


def test_all_covered_is_complete(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    _profile(ws, ["authz", "secrets"])
    write_findings(ws, [_f("authz", FindingStatus.NEEDS_DEPLOYMENT_TESTING, "A-1"),
                        _f("secrets", FindingStatus.REJECTED, "S-1")])
    led = build_coverage_ledger(ws)
    disp = {s["id"]: s["disposition"] for s in led["surfaces"]}
    assert disp["authz"] == "reported"
    assert disp["secrets"] == "no_issue_found"
    assert led["completeness"] == "complete"
    assert validate_coverage_ledger(led) == []


def test_deps_excluded_and_no_profile_is_unknown(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()  # no profile written
    led = build_coverage_ledger(ws)
    assert led["completeness"] == "unknown"
    assert led["surfaces"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_coverage_ledger.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_coverage_ledger'`.

- [ ] **Step 3: Write minimal implementation**

Add to `coverage_ledger.py`:

```python
import json
from pathlib import Path

from sec_harness.models import FindingStatus
from sec_harness.workspace import Workspace, read_findings

_REPORTED = {FindingStatus.CONFIRMED, FindingStatus.FIXED, FindingStatus.NEEDS_DEPLOYMENT_TESTING}
_SETTLED_NO_ISSUE = {FindingStatus.REJECTED, FindingStatus.INFORMATIONAL}


def build_coverage_ledger(ws: Workspace) -> dict:
    """Derive + persist the coverage-completeness ledger from attack_surface × findings.

    One surface per non-``deps`` ``attack_surface`` class:
    ``reported`` (≥1 confirmed/fixed/needs-deployment-testing finding), ``no_issue_found``
    (only rejected/informational findings), or ``needs_follow_up`` (no finding at all — an
    uncovered class). ``completeness`` is ``complete`` only when no surface needs follow-up,
    else ``partial``; ``unknown`` when there is no scan-profile. Writes
    ``kb/coverage-ledger.json`` and returns the ledger.

    Args:
        ws: Workspace to read the profile + findings from and write the ledger into.

    Returns:
        The coverage-ledger dict (also persisted).
    """
    prof_path = ws.kb / "scan-profile.json"
    if not prof_path.exists():
        ledger = {"completeness": "unknown", "surfaces": [], "deferred": [], "open_questions": []}
        ws.kb.mkdir(parents=True, exist_ok=True)
        (ws.kb / "coverage-ledger.json").write_text(json.dumps(ledger, indent=2))
        return ledger
    profile = json.loads(prof_path.read_text())
    classes = [c for c in profile.get("attack_surface", []) if c != "deps"]
    by_cls: dict[str, list] = {}
    for f in read_findings(ws):
        by_cls.setdefault(f.cls, []).append(f.status)
    surfaces = []
    for cls in classes:
        statuses = by_cls.get(cls, [])
        if any(s in _REPORTED for s in statuses):
            disp = "reported"
        elif statuses and all(s in _SETTLED_NO_ISSUE for s in statuses):
            disp = "no_issue_found"
        elif statuses:
            disp = "no_issue_found"  # only non-terminal leftovers; not an uncovered gap
        else:
            disp = "needs_follow_up"
        surfaces.append({"id": cls, "disposition": disp})
    completeness = "complete" if not any(s["disposition"] == "needs_follow_up"
                                         for s in surfaces) else "partial"
    ledger = {"completeness": completeness, "surfaces": surfaces,
              "deferred": [], "open_questions": []}
    (ws.kb / "coverage-ledger.json").write_text(json.dumps(ledger, indent=2))
    return ledger
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_coverage_ledger.py -v`
Expected: PASS (3). `uv run ruff check sec_harness/coverage_ledger.py tests/test_coverage_ledger.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/coverage_ledger.py skills/sec-harness/helpers/tests/test_coverage_ledger.py
git status
git commit -m "feat(coverage-ledger): build ledger from attack_surface x finding status"
```

---

### Task 2: `write_report` builds the ledger when absent + includes NDT in findings.json

**Files:**
- Modify: `helpers/sec_harness/report.py:224-247` (`write_report`)
- Test: `helpers/tests/test_report.py` (create if absent)

**Interfaces:**
- Consumes: `build_coverage_ledger(ws)` (Task 1).
- Produces: `write_report` — when `kb/coverage-ledger.json` is absent, calls `build_coverage_ledger(ws)` and renders it (an uncovered class now surfaces in every report); `findings.json` contains BOTH reportable (confirmed/fixed) AND `needs-deployment-testing` findings, each with its `status` field so consumers distinguish. SARIF stays reportable-only (confirmed/fixed are the actionable results; NDT is a manual-test lead — unchanged).

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_report.py
from __future__ import annotations

import json
from pathlib import Path

from sec_harness.report import write_report
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, write_findings


def _f(fid, status, cls="authz", sev=Severity.MEDIUM):
    return Finding(id=fid, rule_id="r", cls=cls, status=status, severity=sev,
                   file="a.py", line=1, message="m", evidence_sources=["semgrep:x"])


def _profile(ws, attack_surface):
    ws.kb.mkdir(parents=True, exist_ok=True)
    (ws.kb / "scan-profile.json").write_text(json.dumps({
        "languages": [], "frameworks": [], "entrypoints": [], "runnable": False,
        "attack_surface": attack_surface, "sast_plan": {}, "agents_to_spawn": attack_surface,
        "budget_hint": {}}))


def test_findings_json_includes_ndt(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure(); _profile(ws, ["authz"])
    write_findings(ws, [_f("C-1", FindingStatus.CONFIRMED),
                        _f("N-1", FindingStatus.NEEDS_DEPLOYMENT_TESTING)])
    write_report(ws)
    ids = {f["id"]: f["status"] for f in json.loads(ws.findings_json_path.read_text())}
    assert ids["C-1"] == "confirmed"
    assert ids["N-1"] == "needs-deployment-testing"  # NDT now present


def test_report_auto_builds_coverage_ledger_and_shows_gap(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure(); _profile(ws, ["authz", "sqli"])
    write_findings(ws, [_f("C-1", FindingStatus.CONFIRMED, cls="authz")])  # sqli uncovered
    write_report(ws)
    assert (ws.kb / "coverage-ledger.json").exists()
    assert "Coverage completeness" in ws.report_path.read_text()
    assert json.loads((ws.kb / "coverage-ledger.json").read_text())["completeness"] == "partial"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_report.py -v`
Expected: FAIL — `N-1` absent from `findings.json` (reportable-only) and `coverage-ledger.json` not created.

- [ ] **Step 3: Write minimal implementation**

In `report.py` `write_report`, after the `cl_path`/`coverage_ledger` load lines, build the ledger when absent:

```python
    cl_path = ws.kb / "coverage-ledger.json"
    if not cl_path.exists():
        from sec_harness.coverage_ledger import build_coverage_ledger  # local: avoid cycle
        build_coverage_ledger(ws)
    coverage_ledger = json.loads(cl_path.read_text()) if cl_path.exists() else None
```

And change the `findings.json` write (currently `[f.to_dict() for f in reportable]`) to include NDT:

```python
    findings_out = reportable + ndt
    ws.findings_json_path.write_text(json.dumps([f.to_dict() for f in findings_out], indent=2))
```

(`ndt` is already computed at `report.py:226`. `to_dict` carries `status`, so consumers distinguish. SARIF line is unchanged — reportable-only.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_report.py -v`
Expected: PASS (2). Run existing report tests: `uv run pytest -k report -q`. `uv run ruff check sec_harness/report.py tests/test_report.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/report.py skills/sec-harness/helpers/tests/test_report.py
git status
git commit -m "feat(report): auto-build coverage ledger + include needs-deployment-testing in findings.json"
```

---

### Task 3: `scan_options` methodology knobs on `ScanProfile`

**Files:**
- Modify: `helpers/sec_harness/profile.py:42-91`
- Test: `helpers/tests/test_profile.py` (create if absent)
- Modify: `references/scan-profile.schema.json`

**Interfaces:**
- Produces: `ScanProfile.scan_options: dict` (default `{}`), serialized by `to_dict`, accepted by `from_dict`. `validate_profile` reports an error if `scan_options` is present and not a dict. Documented keys (all optional, orchestrator-read): `adversary_depth` (`"full"` | `"gate-by-exception"`), `model_tier_map` (`{phase: tier}`), `wave_k` (int), `max_waves` (int), `token_budget` (int).

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_profile.py
from __future__ import annotations

import json
from pathlib import Path

from sec_harness.profile import ScanProfile, load_profile, save_profile, validate_profile


def _base(**kw) -> dict:
    d = {"languages": [], "frameworks": [], "entrypoints": [], "runnable": False,
         "attack_surface": [], "sast_plan": {}, "agents_to_spawn": [], "budget_hint": {}}
    d.update(kw)
    return d


def test_scan_options_roundtrips(tmp_path: Path):
    p = tmp_path / "sp.json"
    save_profile(p, ScanProfile(scan_options={"adversary_depth": "gate-by-exception",
                                              "wave_k": 3, "token_budget": 500000}))
    prof = load_profile(p)
    assert prof.scan_options["adversary_depth"] == "gate-by-exception"
    assert prof.scan_options["wave_k"] == 3


def test_absent_scan_options_defaults_empty(tmp_path: Path):
    p = tmp_path / "sp.json"; p.write_text(json.dumps(_base()))
    assert load_profile(p).scan_options == {}


def test_non_dict_scan_options_rejected():
    assert any("scan_options" in e for e in validate_profile(_base(scan_options=["x"])))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_profile.py -v`
Expected: FAIL — `ScanProfile` has no `scan_options` (roundtrip `AttributeError`/`TypeError`) and validate does not check it.

- [ ] **Step 3: Write minimal implementation**

In `profile.py`: add the field after `attack_surface_evidence`:

```python
    scan_options: dict = field(default_factory=dict)
```

Update the docstring Attributes with a `scan_options` entry (verbatim):
"scan_options: Optional process knobs the orchestrator reads: ``adversary_depth`` (``full`` | ``gate-by-exception``), ``model_tier_map`` (phase→tier), ``wave_k``/``max_waves`` (investigate saturation), ``token_budget``. Never required; absent ⇒ full depth + defaults."

Add `scan_options` to the dict-validation set:

```python
_DICT_FIELDS = ("sast_plan", "budget_hint")
_OPTIONAL_DICT_FIELDS = ("scan_options",)
```

and in `validate_profile`, after the `_DICT_FIELDS` loop:

```python
    for key in _OPTIONAL_DICT_FIELDS:
        if key in d and not isinstance(d[key], dict):
            errors.append(f"field {key} must be an object")
```

(Do NOT add `scan_options` to `_REQUIRED` — it is optional; old profiles without it still validate.)

- [ ] **Step 4: Update the schema doc**

In `references/scan-profile.schema.json`, add a `scan_options` property (object, not required) documenting the keys — mirror the existing `budget_hint` property style.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_profile.py -v`
Expected: PASS (3). Run the full profile-dependent set: `uv run pytest -k profile -q`. `uv run ruff check sec_harness/profile.py tests/test_profile.py && uv run ty check` — clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/profile.py skills/sec-harness/helpers/tests/test_profile.py skills/sec-harness/references/scan-profile.schema.json
git status
git commit -m "feat(profile): scan_options knobs (adversary_depth, model_tier_map, wave, budget)"
```

---

### Task 4: SKILL.md methodology playbook

**Files:**
- Modify: `skills/sec-harness/SKILL.md`
- Test: `helpers/tests/test_docs_invariants.py` (extend the existing file from Plan 1)

**Interfaces:**
- Produces: a "Process methodology" section in SKILL.md documenting the knobs + the judgement rules, plus a doc-contract test asserting the section exists.

- [ ] **Step 1: Write the failing test**

```python
# add to helpers/tests/test_docs_invariants.py
def test_skill_documents_methodology_playbook():
    txt = _SKILL.read_text()
    assert "adversary_depth" in txt
    assert "gate-by-exception" in txt
    assert "model_tier_map" in txt
    # family-diversity must remain a hard invariant, not a knob
    assert "family" in txt.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_docs_invariants.py::test_skill_documents_methodology_playbook -v`
Expected: FAIL — the section does not exist yet.

- [ ] **Step 3: Write the playbook**

Add a "## Process methodology (knobs + playbook)" section to SKILL.md (read the file first; place it near the audit-driver / cost sections). Cover, in prose the driver follows:
- **`scan_options.adversary_depth`** — `full` (default): every analysis phase (recon/architecture/threat-model/C1) runs its opus phase-adversary. `gate-by-exception`: run the deterministic `phase_gate` always; spawn the opus phase-adversary only when a phase adds material NEW claims beyond already-adversary-validated context (e.g. reuse the context-adversary's map as architecture when it only restates it). **`gate-by-exception` filters what enters the FP ladder — it NEVER lets a finding reach `confirmed` without a mechanical tool receipt; the finding-side FP ladder (critic→judge→validate) always runs at full strength.**
- **`scan_options.model_tier_map`** — phase→tier overrides. Default table: sonnet for recon/architecture/threat-model/context-ingest/investigate/critic/redteam; opus for adversarial-validate, patch, phase-adversary, redteam-adversary, context-adversary; a cheap tier (haiku) for pure-transcription implementer work. **Model-FAMILY diversity is a HARD invariant, not a knob: the adversarial validator must be a different/stronger family than the sonnet producer; if only one family is available, degrade to a fresh-context validator and LOG it — never let the finder be the sole confirmer.**
- **`scan_options.wave_k` / `max_waves`** — override the discovery-ledger saturation knobs (defaults K=2 / max_waves=5) passed to `new_ledger(...)`.
- **`scan_options.token_budget`** — soft per-scan output-token target; scale investigate fan-out width + optional tuning rounds to it.
- **Authoring-KB-from-adversary-context** — when the context phase's opus adversary has already enumerated components/trust-boundaries with cited file:line, the orchestrator MAY author `architecture.md`/`THREAT_MODEL.md` directly from that verified output instead of spawning fresh agents — but only under `adversary_depth: gate-by-exception`, and every finding still passes the full FP ladder.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_docs_invariants.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/SKILL.md skills/sec-harness/helpers/tests/test_docs_invariants.py
git status
git commit -m "docs(skill): process-methodology playbook — depth/tier/wave/budget knobs + hard family-diversity"
```

---

### Task 5: Full-suite regression + wiring note

**Files:**
- Modify: `skills/sec-harness/SKILL.md` (one line in the Report phase pointing at the auto-built ledger)
- Test: run the whole suite; no new source.

- [ ] **Step 1: Add the wiring note**

In SKILL.md's Report phase (step 14), add: "Report auto-builds `kb/coverage-ledger.json` from `attack_surface × finding status` when absent (`coverage_ledger.build_coverage_ledger`); a class with no confirmed/NDT finding blocks `completeness==complete`. `findings.json` now carries confirmed/fixed **and** needs-deployment-testing findings (distinguished by `status`)."

- [ ] **Step 2: Run the full suite**

Run: `cd skills/sec-harness/helpers && uv run pytest -q`
Expected: only the known env-only failures (gitignored bench corpus; semgrep-rules submodule absent — CLAUDE.md §2). Zero NEW failures. If a report/profile-dependent test broke, fix it to the new behavior (do not weaken the coverage invariant).

- [ ] **Step 3: Lint + types clean**

Run: `cd skills/sec-harness/helpers && uv run ruff check sec_harness/ tests/ && uv run ty check`
Expected: no NEW violations in Plan-3-touched files (pre-existing debt in untouched files is out of scope).

- [ ] **Step 4: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/SKILL.md
git status
git commit -m "docs(skill): note report auto-builds coverage ledger + NDT in findings.json"
```

---

## Self-Review

**1. Spec coverage (Plan 3 = Spec A Theme 4):**
- Populate + enforce coverage-ledger → Task 1 (builder; `partial` when a class is uncovered — the existing validator already forbids `complete`+`needs_follow_up`) + Task 2 (auto-built at report time). ✓
- report.md NDT section → already present; NDT in findings.json → Task 2. ✓
- methodology knobs (`adversary_depth`, `model_tier_map`, wave, budget) → Task 3 (`scan_options`) + schema. ✓
- SKILL.md playbook (gate-by-exception, model-tier, author-KB-from-adversary, family-diversity-hard) → Task 4. ✓
- Report-phase wiring note → Task 5. ✓

**2. Placeholder scan:** No TBD/TODO; every code step has runnable code + concrete assertions.

**3. Type consistency:** `build_coverage_ledger(ws) -> dict` used identically in coverage_ledger.py (def) and report.py (call); ledger dict shape (`completeness`/`surfaces[{id,disposition}]`/`deferred`/`open_questions`) matches `validate_coverage_ledger`/`render_markdown` exactly; disposition strings (`reported`/`no_issue_found`/`needs_follow_up`) are in `coverage_ledger._DISPOSITIONS`; `scan_options` default `{}` consistent across `ScanProfile`/`validate_profile`/tests.

**Contract note:** no change to `models.py`/`evidence.py`/`finding.schema.json`; `ScanProfile` is not frozen. No Go-golden regen, no Go-terminal handoff.
