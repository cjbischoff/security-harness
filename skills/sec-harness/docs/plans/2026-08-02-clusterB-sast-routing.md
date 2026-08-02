# Cluster B — SAST Routing & Noise (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Stop 91% of SAST candidates from flooding the ladder as unrouted noise: demote low-value vendored-rule classes to a new `informational` disposition, and deterministically route real-security candidate classes to an investigate agent even when recon didn't plan for them.

**Architecture:** (1) new terminal `FindingStatus.INFORMATIONAL`; (2) `clsmap.NOISE_CLASSES` + `is_noise_class`; (3) `partition.demote_noise(ws)` marks noise-class candidates `informational`; (4) `partition.reconcile_plan(ws, profile)` returns an `agents_to_spawn` augmented with real-security candidate classes recon omitted (so codeql:sqli/ssrf/etc. always get an agent). Report/FP-ladder ignore `informational`.

**Tech Stack:** Python 3.13 stdlib-only, pytest/ruff/ty. Run from `skills/sec-harness/helpers/`.

## Global Constraints
- stdlib-only; line 100; ruff+ty clean on changed files.
- `informational` is TERMINAL (never re-run) and NEVER enters the confirmed report or the FP ladder as `raw`.
- Noise demotion is recall-safe: only classes in `NOISE_CLASSES` are demoted, and only `candidate`-status findings.
- Evidence: O-025 (91%/81% unrouted), O-027 (76 raw noise flood), O-030 (vendored xss 100% FP).
- Branch `skill-audit-driver-20260731`; stage only `skills/` paths; never `git add -A`.

---

### Task 1: FindingStatus.INFORMATIONAL (terminal, non-reporting)

**Files:** Modify `helpers/sec_harness/models.py` (FindingStatus enum), `helpers/sec_harness/campaign.py` (TERMINAL_STATUSES). Test: `helpers/tests/test_models.py`.

- [ ] **Step 1: failing test** (add to test_models.py):
```python
def test_informational_status_roundtrips_and_is_terminal():
    from sec_harness.models import Finding, FindingStatus
    from sec_harness.campaign import TERMINAL_STATUSES
    f = Finding(id="C-1", rule_id="r", cls="log-injection", status=FindingStatus.INFORMATIONAL,
                severity=__import__("sec_harness.models", fromlist=["Severity"]).Severity.INFO,
                file="a.py", line=1, message="noise")
    d = f.to_dict()
    assert d["status"] == "informational"
    assert Finding.from_dict(d).status is FindingStatus.INFORMATIONAL
    assert FindingStatus.INFORMATIONAL in TERMINAL_STATUSES
```
- [ ] **Step 2: run, expect FAIL** — `uv run pytest tests/test_models.py::test_informational_status_roundtrips_and_is_terminal -v` (no INFORMATIONAL member).
- [ ] **Step 3: implement** — add to `FindingStatus` enum in models.py: `INFORMATIONAL = "informational"`. In `campaign.py`, add `FindingStatus.INFORMATIONAL` to the `TERMINAL_STATUSES` set/collection.
- [ ] **Step 4: run, expect PASS**; full `uv run pytest tests/test_models.py -q`.
- [ ] **Step 5: lint** — `uv run ruff check sec_harness/models.py sec_harness/campaign.py tests/test_models.py && uv run ty check sec_harness/models.py sec_harness/campaign.py`.
- [ ] **Step 6: commit** — `git add skills/sec-harness/helpers/sec_harness/models.py skills/sec-harness/helpers/sec_harness/campaign.py skills/sec-harness/helpers/tests/test_models.py && git commit -m "feat(models): add terminal FindingStatus.INFORMATIONAL for SAST noise (O-027)"`

---

### Task 2: clsmap NOISE_CLASSES

**Files:** Modify `helpers/sec_harness/clsmap.py`. Test: `helpers/tests/test_clsmap.py` (create if absent).

**Interfaces:** Produces `NOISE_CLASSES: frozenset[str]`, `is_noise_class(cls: str) -> bool`.

- [ ] **Step 1: failing test**:
```python
def test_noise_classes():
    from sec_harness.clsmap import NOISE_CLASSES, is_noise_class
    assert is_noise_class("log-injection") and is_noise_class("clear-text-logging")
    assert is_noise_class("unknown")
    assert not is_noise_class("sqli") and not is_noise_class("ssrf")
    assert "log-injection" in NOISE_CLASSES
```
- [ ] **Step 2: run, expect FAIL** — `uv run pytest tests/test_clsmap.py::test_noise_classes -v`.
- [ ] **Step 3: implement** — add to clsmap.py:
```python
# Low-value vendored-rule classes: real code smells but not exploitable findings on their own
# (O-030: xss/log-injection vendored rules ~100% FP on a real backend). Demoted to `informational`
# rather than promoted to `raw`, so they don't flood the FP ladder. `unknown` = a hit with no CWE.
NOISE_CLASSES: frozenset[str] = frozenset({"log-injection", "clear-text-logging", "unknown"})


def is_noise_class(cls: str) -> bool:
    """True if ``cls`` is a low-value vendored-rule class that should not enter the FP ladder as raw."""
    return cls in NOISE_CLASSES
```
- [ ] **Step 4: run PASS**; **Step 5: lint** clsmap.py + test; **Step 6: commit** — `git commit -m "feat(clsmap): NOISE_CLASSES for low-value vendored-rule hits (O-030)"` (stage the two paths).

---

### Task 3: partition.demote_noise + reconcile_plan

**Files:** Modify `helpers/sec_harness/partition.py`. Test: `helpers/tests/test_partition.py`.

**Interfaces:**
- `demote_noise(ws: Workspace) -> int` — sets every `candidate`-status finding whose `cls` is a noise class to `INFORMATIONAL`; returns the count demoted; writes findings.
- `reconcile_plan(ws: Workspace, agents_to_spawn: list[str]) -> list[str]` — returns `agents_to_spawn` plus any candidate class that is (a) not already in it, (b) not `deps`, (c) not a noise class — so a real-security class recon omitted (codeql:sqli/ssrf/…) gets routed. Order: original agents_to_spawn first, then the added classes sorted.

- [ ] **Step 1: failing tests**:
```python
def test_demote_noise_moves_only_noise_candidates(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.workspace import Workspace, read_findings, write_findings
    from sec_harness.partition import demote_noise
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    def c(id_, cls): return Finding(id=id_, rule_id="r", cls=cls, status=FindingStatus.CANDIDATE,
                                    severity=Severity.LOW, file="a.py", line=1, message="m")
    write_findings(ws, [c("C-1", "log-injection"), c("C-2", "sqli"), c("C-3", "clear-text-logging")])
    assert demote_noise(ws) == 2
    by = {f.id: f.status for f in read_findings(ws)}
    assert by["C-1"] is FindingStatus.INFORMATIONAL
    assert by["C-3"] is FindingStatus.INFORMATIONAL
    assert by["C-2"] is FindingStatus.CANDIDATE   # real class untouched


def test_reconcile_plan_adds_real_unrouted_classes(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.workspace import Workspace, write_findings
    from sec_harness.partition import reconcile_plan
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    def c(id_, cls): return Finding(id=id_, rule_id="r", cls=cls, status=FindingStatus.CANDIDATE,
                                    severity=Severity.LOW, file="a.py", line=1, message="m")
    write_findings(ws, [c("C-1", "sqli"), c("C-2", "log-injection"), c("C-3", "deps"), c("C-4", "authz")])
    out = reconcile_plan(ws, ["authz"])   # recon only planned authz; sqli is a real unrouted class
    assert "sqli" in out and "authz" in out
    assert "log-injection" not in out and "deps" not in out   # noise + deps not routed
```
- [ ] **Step 2: run, expect FAIL** — functions undefined.
- [ ] **Step 3: implement** — add to partition.py (reuse existing `partition_candidates_by_class` for the class set):
```python
def demote_noise(ws: Workspace) -> int:
    """Demote candidate findings in a NOISE_CLASS to INFORMATIONAL (they never enter the FP ladder)."""
    from sec_harness.clsmap import is_noise_class
    findings = read_findings(ws)
    n = 0
    for f in findings:
        if f.status is FindingStatus.CANDIDATE and is_noise_class(f.cls):
            f.status = FindingStatus.INFORMATIONAL
            f.history.append({"event": "partition:demoted-noise", "cls": f.cls})
            n += 1
    if n:
        write_findings(ws, findings)
    return n


def reconcile_plan(ws: Workspace, agents_to_spawn: list[str]) -> list[str]:
    """Augment agents_to_spawn with real-security candidate classes recon omitted (O-025)."""
    from sec_harness.clsmap import is_noise_class
    parts = partition_candidates_by_class(ws)
    extra = sorted(
        cls for cls in parts
        if cls not in agents_to_spawn and cls != "deps" and not is_noise_class(cls)
    )
    return list(agents_to_spawn) + extra
```
(Add the needed imports at the top: `read_findings`, `write_findings`, `FindingStatus` — check what's already imported.)
- [ ] **Step 4: run PASS**; full `uv run pytest tests/test_partition.py -q`.
- [ ] **Step 5: lint** partition.py + test.
- [ ] **Step 6: commit** — `git commit -m "feat(partition): demote_noise + reconcile_plan for SAST routing (O-025/O-027)"` (stage the two paths).

---

### Task 4: Wire into SKILL + investigate prompt

**Files:** Modify `skills/sec-harness/SKILL.md` (Phase 2-3 prefilter/investigate section), `skills/sec-harness/agents/investigate.md`. No test (docs).

- [ ] **Step 1: SKILL.md** — in the prefilter/investigate step, add after `run_prefilter`: "Then `demote_noise(ws)` (moves log-injection/clear-text-logging/unknown candidates to `informational`) and `agents = reconcile_plan(ws, profile.agents_to_spawn)` (routes real-security classes recon omitted). Spawn investigate agents over the reconciled `agents`; the general-triage `security-other` agent handles any residual unrouted classes."
- [ ] **Step 2: investigate.md** — in the disposition rules, add: "A candidate already demoted to `informational` (noise class) is out of scope — do not promote it to `raw`. Only escalate a noise-class hit if you find a concrete reachability-from-untrusted indicator, and say so."
- [ ] **Step 3: commit** — `git add skills/sec-harness/SKILL.md skills/sec-harness/agents/investigate.md && git commit -m "docs(sec-harness): wire demote_noise + reconcile_plan into the run (O-025)"`

---

## Self-review
- Spec coverage: GSD Cluster B → Task 1 (informational status), 2 (noise set), 3 (demote + reconcile), 4 (wiring). ✓
- Recall-safe: only NOISE_CLASSES candidates demoted; reconcile ADDS agents (never removes). ✓
- Report/ladder impact: report renders confirmed/fixed only → informational excluded; FP ladder operates on raw → informational excluded. ✓
- Type consistency: `demote_noise(ws)->int`, `reconcile_plan(ws, list[str])->list[str]`, `is_noise_class(str)->bool`, `NOISE_CLASSES: frozenset[str]`. ✓
