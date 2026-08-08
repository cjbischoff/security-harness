# Scoring + Gate Strictness (Spec A · Plan 2 of 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make risk-scoring and disposition honest — score `needs-deployment-testing` findings, let a judge downgrade actually lower the score, deterministically confirm SCA `deps` findings with a reachability note — and harden the few remaining prompt/orchestration gaps, WITHOUT touching the frozen `models.py`/`evidence.py` contract.

**Architecture:** Additive changes to `calibrate.py` (score NDT + honor `judge_verdict` downgrade), a new `campaign.promote_deps` (mirrors the existing `promote_runtime_dependent`, called from `calibrate_findings`), a `reconcile_plan` dedup guard in `partition.py`, and prompt/doc guards. No enum, field, or schema-type change — those were verified already present.

**Tech Stack:** Python 3 stdlib only; `pytest` via `uv run`; `ruff` (line-length 100) + `ty`.

## Global Constraints

- Core is **stdlib-only**. Add NO runtime dependency to `pyproject.toml`.
- **Do NOT modify** `helpers/sec_harness/models.py` or `helpers/sec_harness/evidence.py` — frozen contract mirrored by the Go port. Plan 2 touches NEITHER (verified: `Severity.INFO`, `runtime_dependent`, `runtime_test`/`reachability`/`judge_verdict` fields, and the `_MECHANICAL` whitelist all already exist and suffice). **No Go-golden regen is required by this plan.**
- **You touch only `skills/` paths.** Never `git add -A`; stage explicit `skills/sec-harness/...` paths; `git status` must show only skill paths before every commit. Never touch `go/`.
- Work on branch `spec/scoring-gate-strictness-20260807` (create off `main`). Personal remote → no GPG signing, no AI attribution. Do NOT push.
- Run everything from `skills/sec-harness/helpers/`. Tests in `helpers/tests/`. `uv run pytest`.
- Preserve deterministic-scoring invariant: **risk_score is computed by code, never asserted by an LLM.** `judge_verdict` may only LOWER a score, never raise it (an LLM signal can add caution, never inflate risk).

## Already-verified-present (DO NOT re-implement — cite in reviews if a task drifts toward these)

- `Severity.INFO = "info"` (`models.py:17`). The old `severity:"informational"` failure was an agent writing a *FindingStatus* value into `severity`; the schema enum (`finding.schema.json:16-19`) already rejects it and `findings_gate` returns exit 1.
- `campaign.promote_runtime_dependent` already auto-called in `calibrate_findings` (`calibrate.py:140-142`).
- `evidence.is_tool_receipt` already rejects `Read:*`/`llm-*`; `findings_gate.py:64-72` already fails confirmed/fixed without a mechanical receipt.
- `finding.schema.json:39-41` already types `runtime_test`/`reachability` as `["object","null"]`; `_schema_validate` + `findings_gate.main` already return exit 1 on a string. (The earlier "exit 0" report was a `| tail; echo $?` pipe artifact.)
- `partition.reconcile_plan` already returns distinct extra classes and excludes `deps`.

---

## File Structure

- **Modify** `helpers/sec_harness/calibrate.py` — score `NEEDS_DEPLOYMENT_TESTING`; apply `judge_verdict` downgrade (lower-only); call `promote_deps`.
- **Modify** `helpers/sec_harness/campaign.py` — add `promote_deps(ws) -> int`.
- **Modify** `helpers/sec_harness/partition.py` — `reconcile_plan` returns a de-duplicated list.
- **Modify** `helpers/tests/test_calibrate.py` (create if absent), `helpers/tests/test_campaign.py` (create if absent), `helpers/tests/test_partition.py` (create if absent).
- **Modify** `skills/sec-harness/agents/investigate.md` + `references/prompt-constants.md` — guard: `severity` is one of info/low/medium/high/critical, never a status value.
- **Modify** `skills/sec-harness/SKILL.md` — one-candidate-one-agent dispatch rule.
- **Modify** `skills/sec-harness/docs/dogfooding/2026-08-07-run-observations.md` — correct the over-reported / mis-observed entries.

---

### Task 1: Score `needs-deployment-testing` findings in calibrate

**Files:**
- Modify: `helpers/sec_harness/calibrate.py:145-167` (`calibrate_findings` loop)
- Test: `helpers/tests/test_calibrate.py`

**Interfaces:**
- Consumes: `calibrate_score(finding)` (existing), `FindingStatus.NEEDS_DEPLOYMENT_TESTING`.
- Produces: `calibrate_findings` also sets `risk_score` on `needs-deployment-testing` findings (same `calibrate_score` path as confirmed).

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_calibrate.py
from __future__ import annotations

from pathlib import Path

from sec_harness.calibrate import calibrate_findings
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, write_findings, read_findings


def _f(**kw) -> Finding:
    base = dict(id="F-1", rule_id="r", cls="authz", status=FindingStatus.CONFIRMED,
                severity=Severity.MEDIUM, file="a.py", line=1, message="m",
                evidence_sources=["semgrep:rule"])
    base.update(kw)
    return Finding(**base)


def test_scores_needs_deployment_testing(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f(id="NDT-1", status=FindingStatus.NEEDS_DEPLOYMENT_TESTING,
                           severity=Severity.HIGH, evidence_sources=["structural-index:callers"])])
    n = calibrate_findings(ws)
    out = {f.id: f for f in read_findings(ws)}
    assert out["NDT-1"].risk_score is not None
    assert out["NDT-1"].risk_score >= 6  # high severity floor
    assert n >= 1


def test_still_scores_confirmed(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f(id="C-1", severity=Severity.MEDIUM)])
    calibrate_findings(ws)
    assert read_findings(ws)[0].risk_score is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_calibrate.py::test_scores_needs_deployment_testing -v`
Expected: FAIL — `NDT-1.risk_score` is `None` (calibrate scores only CONFIRMED).

- [ ] **Step 3: Write minimal implementation**

In `calibrate.py` `calibrate_findings`, change the status guard so both `CONFIRMED` and `NEEDS_DEPLOYMENT_TESTING` are scored. Replace the loop guard:

```python
    _SCOREABLE = {FindingStatus.CONFIRMED, FindingStatus.NEEDS_DEPLOYMENT_TESTING}
    for f in findings:
        if f.status in _SCOREABLE:
```

(Everything inside the loop — `_attach_citations`, `_derived_score`, floor, baseline cap, inflation flag, priority — stays identical. `_attach_citations` is a no-op if already set; it is safe on NDT findings.) Define `_SCOREABLE` as a module constant near the other constants.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_calibrate.py -v`
Expected: PASS (2). `uv run ruff check sec_harness/calibrate.py tests/test_calibrate.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/calibrate.py skills/sec-harness/helpers/tests/test_calibrate.py
git status
git commit -m "feat(calibrate): assign risk_score to needs-deployment-testing findings"
```

---

### Task 2: Honor `judge_verdict` downgrade (lower-only) in calibrate

**Files:**
- Modify: `helpers/sec_harness/calibrate.py` (in the `calibrate_findings` per-finding body, after the floor is applied)
- Test: `helpers/tests/test_calibrate.py`

**Interfaces:**
- Consumes: `Finding.judge_verdict` (existing field), `_derived_score` (existing).
- Produces: when `judge_verdict` is `"severity-inflated"` or `"downgrade"`, the finding's `risk_score` drops to the pre-floor `_derived_score` (removing the severity-band floor the inflated severity imposed). Never raises a score. A `calibrate:judge-downgrade-applied` history event is appended.

- [ ] **Step 1: Write the failing test**

```python
# add to helpers/tests/test_calibrate.py
def test_judge_downgrade_lowers_below_severity_floor(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    # HIGH severity (floor 6) but 3 strong preconditions drive derived score low,
    # and the judge said the severity is inflated -> score should follow derived, not the floor.
    write_findings(ws, [_f(id="J-1", severity=Severity.HIGH, judge_verdict="severity-inflated",
                           preconditions=["requires admin", "non-default config", "chained from prior primitive"],
                           evidence_sources=["semgrep:rule"])])
    calibrate_findings(ws)
    f = read_findings(ws)[0]
    assert f.risk_score < 6, "judge severity-inflated must drop below the HIGH floor"
    assert any(h.get("event") == "calibrate:judge-downgrade-applied" for h in f.history)


def test_judge_uphold_does_not_lower(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f(id="U-1", severity=Severity.HIGH, judge_verdict="uphold",
                           evidence_sources=["semgrep:rule"])])
    calibrate_findings(ws)
    assert read_findings(ws)[0].risk_score >= 6  # floor intact
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_calibrate.py::test_judge_downgrade_lowers_below_severity_floor -v`
Expected: FAIL — score is floored to 6 regardless of `judge_verdict`.

- [ ] **Step 3: Write minimal implementation**

In `calibrate_findings`, immediately AFTER `f.risk_score = max(derived, _severity_floor(f.severity))` and the baseline-cap line, add:

```python
                if f.judge_verdict in ("severity-inflated", "downgrade"):
                    lowered = min(f.risk_score, derived)  # drop the severity-band floor; never raise
                    if lowered < f.risk_score:
                        f.history.append({"event": "calibrate:judge-downgrade-applied",
                                          "judge_verdict": f.judge_verdict,
                                          "from": f.risk_score, "to": lowered})
                        f.risk_score = lowered
```

(`derived` is already computed above as `_derived_score(f)`. This only ever lowers — preserving the "LLM never inflates risk" invariant.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_calibrate.py -v`
Expected: PASS (4 total). `uv run ruff check sec_harness/calibrate.py tests/test_calibrate.py && uv run ty check` — clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/calibrate.py skills/sec-harness/helpers/tests/test_calibrate.py
git status
git commit -m "feat(calibrate): judge downgrade lowers risk below the severity floor (lower-only)"
```

---

### Task 3: Deterministic `deps` → confirmed promotion with reachability heuristic

**Files:**
- Modify: `helpers/sec_harness/campaign.py` (add `promote_deps`, mirroring `promote_runtime_dependent`)
- Modify: `helpers/sec_harness/calibrate.py` (call `promote_deps(ws)` alongside `promote_runtime_dependent(ws)`)
- Test: `helpers/tests/test_campaign.py`

**Interfaces:**
- Consumes: `evidence.is_tool_receipt` (existing), `FindingStatus`, `Finding.reachability`.
- Produces: `campaign.promote_deps(ws) -> int` — promotes each `candidate` finding with `cls=="deps"` AND ≥1 mechanical SCA receipt (an `evidence_sources` entry starting `sca`) to `CONFIRMED`; sets `reachability = {"reachable": <bool|None>, "blocker": <str|None>, "chain": []}` where a lockfile-only path (file basename in the lockfile set) yields `reachable=False, blocker="dev-build-dependency-not-runtime-verified"`, else `reachable=None, blocker=None` (present-but-unverified). Appends a `campaign:promoted-deps` history event. Returns the count promoted.

- [ ] **Step 1: Read the sibling to match the pattern**

Run: `cd skills/sec-harness/helpers && uv run python -c "import inspect, sec_harness.campaign as c; print(inspect.getsource(c.promote_runtime_dependent))"`
Mirror its read → mutate → `write_findings` shape and its `TERMINAL_STATUSES`/history conventions.

- [ ] **Step 2: Write the failing test**

```python
# helpers/tests/test_campaign.py
from __future__ import annotations

from pathlib import Path

from sec_harness.campaign import promote_deps
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, write_findings, read_findings


def _dep(**kw) -> Finding:
    base = dict(id="C-1", rule_id="osv:GHSA-x", cls="deps", status=FindingStatus.CANDIDATE,
                severity=Severity.HIGH, file="package-lock.json", line=1, message="vuln dep",
                evidence_sources=["sca:osv:GHSA-x"])
    base.update(kw)
    return Finding(**base)


def test_promote_deps_confirms_with_sca_receipt(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_dep()])
    n = promote_deps(ws)
    f = read_findings(ws)[0]
    assert n == 1
    assert f.status is FindingStatus.CONFIRMED
    assert f.reachability == {"reachable": False,
                              "blocker": "dev-build-dependency-not-runtime-verified", "chain": []}


def test_promote_deps_ignores_non_sca_candidate(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_dep(id="C-2", evidence_sources=["llm-claimed:dep"])])
    assert promote_deps(ws) == 0
    assert read_findings(ws)[0].status is FindingStatus.CANDIDATE


def test_promote_deps_non_lockfile_marks_unverified(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_dep(id="C-3", file="src/vendor/thing.go")])
    promote_deps(ws)
    f = read_findings(ws)[0]
    assert f.status is FindingStatus.CONFIRMED
    assert f.reachability == {"reachable": None, "blocker": None, "chain": []}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_campaign.py -v`
Expected: FAIL with `ImportError: cannot import name 'promote_deps'`.

- [ ] **Step 4: Write minimal implementation**

Add to `campaign.py` (place near `promote_runtime_dependent`):

```python
_LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Gemfile.lock",
    "go.sum", "go.mod", "poetry.lock", "Pipfile.lock", "requirements.txt",
    "Cargo.lock", "composer.lock",
}


def promote_deps(ws: Workspace) -> int:
    """Promote SCA ``deps`` candidates to confirmed with a reachability note.

    A ``deps`` finding carrying a mechanical SCA receipt (an ``evidence_sources`` entry
    beginning ``sca``) provably identifies a vulnerable dependency, so it is confirmed
    deterministically (no investigate agent routes ``deps``). A lockfile-only hit is marked
    ``reachable=False`` (present in the dependency graph but not shown reachable from runtime
    code — a dev/build/transitive dependency until proven otherwise); any other path is marked
    ``reachable=None`` (present, runtime reachability unverified). LLM-only ``deps`` candidates
    are left untouched — the SCA receipt is the ground.

    Args:
        ws: Workspace whose ``deps`` candidates are promoted in place.

    Returns:
        The number of findings promoted.
    """
    from sec_harness.evidence import is_tool_receipt  # local: keep import graph flat
    findings = read_findings(ws)
    n = 0
    dirty = False
    for f in findings:
        if f.status is not FindingStatus.CANDIDATE or f.cls != "deps":
            continue
        if not any(s.startswith("sca") and is_tool_receipt(s) for s in f.evidence_sources):
            continue
        f.status = FindingStatus.CONFIRMED
        lockfile_only = Path(f.file).name in _LOCKFILES
        f.reachability = {
            "reachable": False if lockfile_only else None,
            "blocker": "dev-build-dependency-not-runtime-verified" if lockfile_only else None,
            "chain": [],
        }
        f.history.append({"event": "campaign:promoted-deps", "lockfile_only": lockfile_only})
        n += 1
        dirty = True
    if dirty:
        write_findings(ws, findings)
    return n
```

Ensure `from pathlib import Path`, `read_findings`, `write_findings`, `FindingStatus` are imported in `campaign.py` (add any missing). Then in `calibrate.py` `calibrate_findings`, add the call beside the existing promotion:

```python
    from sec_harness.campaign import promote_deps  # local: avoid cycle
    promote_runtime_dependent(ws)
    promote_deps(ws)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_campaign.py tests/test_calibrate.py -v`
Expected: PASS. `uv run ruff check sec_harness/campaign.py sec_harness/calibrate.py tests/test_campaign.py && uv run ty check` — clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/campaign.py skills/sec-harness/helpers/sec_harness/calibrate.py skills/sec-harness/helpers/tests/test_campaign.py
git status
git commit -m "feat(campaign): deterministic deps->confirmed promotion with reachability heuristic"
```

---

### Task 4: `reconcile_plan` dedup guard + prompt/doc guards

**Files:**
- Modify: `helpers/sec_harness/partition.py:93-112` (`reconcile_plan`)
- Test: `helpers/tests/test_partition.py`
- Modify: `skills/sec-harness/references/prompt-constants.md` + `agents/investigate.md` (severity-value guard)
- Modify: `skills/sec-harness/SKILL.md` (one-candidate-one-agent rule)

**Interfaces:**
- Produces: `reconcile_plan` returns a list with NO duplicate class (a class present twice in the input `agents_to_spawn`, or added twice, appears once), preserving first-seen order then sorted extras.

- [ ] **Step 1: Write the failing test**

```python
# helpers/tests/test_partition.py
from __future__ import annotations

from pathlib import Path

from sec_harness.partition import reconcile_plan
from sec_harness.workspace import Workspace


def test_reconcile_plan_dedupes_input(tmp_path: Path):
    ws = Workspace(tmp_path); ws.ensure()  # no candidates -> no extras
    out = reconcile_plan(ws, ["authz", "secrets", "authz"])
    assert out == ["authz", "secrets"], "duplicate planned class must appear once"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_partition.py -v`
Expected: FAIL — output is `["authz", "secrets", "authz"]` (input duplicates preserved).

- [ ] **Step 3: Write minimal implementation**

In `partition.py` `reconcile_plan`, de-duplicate the base list preserving order before appending extras:

```python
    parts = partition_candidates_by_class(ws)
    seen: set[str] = set()
    base: list[str] = []
    for cls in agents_to_spawn:
        if cls not in seen:
            seen.add(cls)
            base.append(cls)
    extra = sorted(
        cls for cls, fs in parts.items()
        if cls not in seen and cls != "deps" and not is_noise_class(cls)
        and any(f.status is FindingStatus.CANDIDATE for f in fs)
    )
    return base + extra
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_partition.py -v`
Expected: PASS. `uv run ruff check sec_harness/partition.py tests/test_partition.py && uv run ty check` — clean.

- [ ] **Step 5: Prompt + SKILL doc guards**

In `references/prompt-constants.md`, add to the severity guidance block (verbatim):
"SEVERITY VALUES: `severity` is exactly one of `info | low | medium | high | critical`. NEVER put a status value (`informational`, `needs-deployment-testing`, `candidate`) in `severity` — those are `status` values. A finding whose `severity` is not one of the five bands is rejected by the gate."
In `agents/investigate.md`, add a one-line reminder next to where severity is set: "severity ∈ {info,low,medium,high,critical}; disposition like `needs-deployment-testing` goes in `status`, never `severity`."
In `SKILL.md` (investigate dispatch section), add: "**One candidate, one agent.** Each candidate's `cls` routes it to exactly one investigate agent (`partition_candidates_by_class`). Never hand the same candidate/file to two class agents in parallel — concurrent writers to one finding file race (last-writer-wins). If a candidate looks cross-class, pick the primary class; the others hunt by shape."

- [ ] **Step 6: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/helpers/sec_harness/partition.py skills/sec-harness/helpers/tests/test_partition.py skills/sec-harness/references/prompt-constants.md skills/sec-harness/agents/investigate.md skills/sec-harness/SKILL.md
git status
git commit -m "fix(partition): dedupe reconcile_plan + severity-value and one-candidate-one-agent guards"
```

---

### Task 5: Correct the run-observations log + full-suite regression

**Files:**
- Modify: `skills/sec-harness/docs/dogfooding/2026-08-07-run-observations.md`
- Test: run the whole suite; no new source.

- [ ] **Step 1: Correct the over-reported / mis-observed entries**

In `docs/dogfooding/2026-08-07-run-observations.md`, add a `## Corrections (2026-08-07, verified in source)` section stating verbatim which logged items were already-fixed or mis-observed, so the record is honest:
- "🔴 gate warns-not-fails on schema-type violation — **WITHDRAWN**: a `| tail; echo $?` pipe masked the real exit; `finding.schema.json:39-41` types `runtime_test`/`reachability` and `findings_gate.main` returns exit 1 on a violation. No code change needed."
- "🟠 `severity: informational` rejected by enum — **as-designed**: `Severity.INFO='info'` exists; `informational` is a *status* value an agent wrongly put in `severity`. Fixed by prompt guard (Plan 2 T4), not an enum change."
- "🔴 `calibrate` never scores needs-deployment-testing — **confirmed real**, fixed in Plan 2 T1."
- "🔴 judge severity-cap not applied — **confirmed real**, fixed in Plan 2 T2 (lower-only)."
- "🟡 deps not auto-promoted — **confirmed real**, fixed in Plan 2 T3. `promote_runtime_dependent` was already auto-called (ISSUE-027 done)."
- "🟡 same candidate routed to two agents — **operator error, not a code bug**: `partition` assigns one `cls` per candidate; the double-dispatch was a hand-authored orchestration mistake. Guarded by the SKILL one-candidate-one-agent rule (Plan 2 T4)."

- [ ] **Step 2: Run the full suite**

Run: `cd skills/sec-harness/helpers && uv run pytest -q`
Expected: only the known env-only failures (gitignored bench corpus; semgrep-rules submodule absent in this repo — CLAUDE.md §2). Zero NEW failures. If a calibrate/campaign-dependent test broke, fix it to the new behavior (do not weaken the invariants).

- [ ] **Step 3: Lint + types clean**

Run: `cd skills/sec-harness/helpers && uv run ruff check sec_harness/ tests/ && uv run ty check`
Expected: no NEW violations in Plan-2-touched files (pre-existing debt in untouched files, per Plan 1 Task 7, is out of scope).

- [ ] **Step 4: Commit**

```bash
cd /Users/christopher/Tools/security-harness
git add skills/sec-harness/docs/dogfooding/2026-08-07-run-observations.md
git status
git commit -m "docs: correct run-observations — withdraw mis-observed gate/enum items, mark real fixes"
```

---

## Self-Review

**1. Spec coverage (Plan 2 = Spec A Theme 2 + Theme 3):**
- calibrate scores needs-deployment-testing → Task 1. ✓
- judge_verdict cap → Task 2 (lower-only, honors the no-LLM-inflation invariant). ✓
- `Severity.INFO` → already present; the real bug (status-in-severity) → Task 4 prompt guard + existing gate. ✓
- deps→confirmed + reachability heuristic → Task 3. ✓
- gate hard-fail on schema-type violation → already present (withdrawn, Task 5 correction). ✓
- evidence-whitelist gate → already present (`findings_gate.py:64-72`). ✓ (no task; cited in Task 5.)
- partition dedup / double-dispatch → Task 4 (code dedup + SKILL rule). ✓
- `promote_runtime_dependent` auto-call → already present. ✓ (cited Task 5.)

**2. Placeholder scan:** No TBD/TODO; every code step has runnable code and concrete assertions.

**3. Type consistency:** `promote_deps(ws) -> int` used identically in campaign.py (def) and calibrate.py (call); `_SCOREABLE` set and `judge_verdict` string values (`"severity-inflated"`, `"downgrade"`, `"uphold"`) match `models.py` docstring; `reachability` dict shape (`reachable`/`blocker`/`chain`) matches `models.py:79-81`; `reconcile_plan` return type unchanged (`list[str]`).

**Contract note:** verified NO change to `models.py`/`evidence.py`/`finding.schema.json` types — so no Go-golden regen and no Go-terminal handoff is required by this plan.
