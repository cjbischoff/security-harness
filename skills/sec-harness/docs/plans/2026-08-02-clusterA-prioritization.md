# Cluster A — Prioritization & Risk Correctness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `risk_score` from inverting against severity so a confirmed critical never ranks below a medium or falls below the red-team action bar.

**Architecture:** Three changes in the deterministic scoring path. (1) `calibrate.py` weights preconditions by *difficulty* not count, so free preconditions (`unauthenticated`) no longer lower risk. (2) `calibrate.py` applies a per-severity floor so ordering can't invert, while inflation-flagging compares against the *pre-floor* derived score so the advisory signal survives. (3) `redteam.py` makes the plan's action bar disposition+severity-aware so `--min-risk` can't hide a critical/high.

**Tech Stack:** Python 3.13, stdlib-only core, `pytest`, `ruff`, `ty`. Run everything from `skills/sec-harness/helpers/`.

## Global Constraints

- Core is **stdlib-only** — no new runtime dependencies.
- Line length 100; `ruff check` and `ty check` must be clean before each commit.
- `risk_score` is an int in `[1,10]`; the harness computes it deterministically (LLMs never assert it).
- Work on branch `skill-audit-driver-20260731`; stage only `skills/` paths; never `git add -A`.
- Evidence source for this cluster: `O-031` / `O-015` / `O-016` (coterie-backend run: NoSQL-ATO critical scored 5, below a medium at 8).

---

### Task 1: Difficulty-weighted precondition cap

**Files:**
- Modify: `helpers/sec_harness/calibrate.py` (`_PRECOND_CAP`, `_precondition_cap`; add weight constants + `_precondition_weight`)
- Test: `helpers/tests/test_calibrate.py`

**Interfaces:**
- Produces: `_precondition_weight(preconditions: list[str]) -> float`; `_precondition_cap(preconditions: list[str]) -> int` (signature CHANGES from `(n: int)`).
- Consumes: nothing new.

- [ ] **Step 1: Write the failing test** — add to `test_calibrate.py`:

```python
def test_precondition_weight_ignores_free_preconditions():
    from sec_harness.calibrate import _precondition_weight
    # unauthenticated / no-config / public are NOT mitigants -> weight 0
    assert _precondition_weight(
        ["unauthenticated buyer reaching checkout", "no config required", "public endpoint"]
    ) == 0.0
    # a real barrier counts; "unauth" containing "auth" must not misclassify as weak
    assert _precondition_weight(["requires admin token"]) == 1.0
    assert _precondition_weight(["authenticated low-priv user"]) == 0.5


def test_precondition_cap_uses_weight_not_count():
    from sec_harness.calibrate import _precondition_cap
    # three FREE preconditions -> weight 0 -> no cap (was: count 3 -> cap 5)
    assert _precondition_cap(["unauthenticated", "remote", "no setup"]) == 10
    # one strong barrier -> weight 1 -> cap 8
    assert _precondition_cap(["requires admin token"]) == 8
    # two strong -> weight 2 -> cap 7
    assert _precondition_cap(["requires admin token", "non-default config"]) == 7
    # three strong -> weight 3 -> cap 5
    assert _precondition_cap(["admin", "non-default config", "local access"]) == 5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_calibrate.py::test_precondition_weight_ignores_free_preconditions tests/test_calibrate.py::test_precondition_cap_uses_weight_not_count -v`
Expected: FAIL (`_precondition_weight` undefined; `_precondition_cap` takes an int).

- [ ] **Step 3: Write minimal implementation** — in `calibrate.py`, replace the `_PRECOND_CAP` block and `_precondition_cap`:

```python
# A precondition lowers risk only when it is a real barrier an attacker must overcome.
# Free conditions (unauthenticated/remote/default) are NOT mitigants and never lower risk
# (fixes O-031: enumerating free preconditions must not penalize a finding).
_PRECOND_FREE = ("unauth", "no auth", "without auth", "anonymous", "public", "no config",
                 "default config", "no setup", "remote", "any user", "no special", "no privilege")
_PRECOND_STRONG = ("admin", "operator", "root", "superuser", "non-default", "feature flag",
                   "feature-flag", "local access", "local-only", "physical", "prior primitive",
                   "prior-primitive", "chained", "mitm", "man-in-the-middle", "cfg", "config",
                   "specific config", "guessed", "brute")
_PRECOND_WEAK = ("auth", "login", "logged", "session", "account", "one hop", "csrf",
                 "user interaction")


def _precondition_weight(preconditions: list[str]) -> float:
    """Summed difficulty weight of preconditions (free=0, weak=0.5, strong=1.0, unknown=0)."""
    total = 0.0
    for p in preconditions:
        s = p.lower()
        if any(k in s for k in _PRECOND_FREE):
            continue  # non-mitigant; checked first so "unauth..." never matches weak "auth"
        if any(k in s for k in _PRECOND_STRONG):
            total += 1.0
        elif any(k in s for k in _PRECOND_WEAK):
            total += 0.5
    return total


def _precondition_cap(preconditions: list[str]) -> int:
    """Risk ceiling from precondition DIFFICULTY (weight), not count.

    Args:
        preconditions: The finding's precondition strings.

    Returns:
        Ceiling in ``[5, 10]``: ``w<1 -> 10``, ``1<=w<2 -> 8``, ``2<=w<3 -> 7``, ``w>=3 -> 5``.
    """
    w = _precondition_weight(preconditions)
    if w < 1:
        return 10
    if w < 2:
        return 8
    if w < 3:
        return 7
    return 5
```

Then update the call site in `calibrate_score` (currently `raw = min(raw, _precondition_cap(len(finding.preconditions)))`):

```python
    raw = min(raw, _precondition_cap(finding.preconditions))
```

- [ ] **Step 4: Update the pre-existing test that encoded count-based behavior**

Replace `test_precondition_cap_lowers_score` with the weight-based expectations (the OLD values were the O-031 bug):

```python
def test_precondition_cap_lowers_score():
    crit_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 -> 10
    assert calibrate_score(_crit(crit_vec, [])) == 10                       # weight 0 -> no cap
    assert calibrate_score(_crit(crit_vec, ["unauthenticated"])) == 10      # free -> no cap
    assert calibrate_score(_crit(crit_vec, ["requires admin token",
                                            "non-default config",
                                            "local access"])) == 8          # weight 3 -> cap 5, floored 8
```
(The floor-to-8 in the third assertion is delivered by Task 2; if running Task 1 alone, that line reads `== 5` — but implement Task 2 before committing the cluster so the file's final state matches.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_calibrate.py -v`
Expected: the new weight tests PASS. (`test_precondition_cap_lowers_score` third assertion + `test_inflation_flag_recorded` are finalized in Task 2 — they may still fail here; that's expected mid-cluster.)

- [ ] **Step 6: Lint**

Run: `uv run ruff check sec_harness/calibrate.py tests/test_calibrate.py && uv run ty check`
Expected: clean.

---

### Task 2: Severity floor + pre-floor inflation

**Files:**
- Modify: `helpers/sec_harness/calibrate.py` (`calibrate_score`, `calibrate_findings`; add `_SEVERITY_FLOOR`, `_derived_score`)
- Test: `helpers/tests/test_calibrate.py`

**Interfaces:**
- Produces: `_severity_floor(severity: Severity) -> int`; `_derived_score(finding) -> int` (pre-floor score, used by inflation). `calibrate_score(finding)` return semantics unchanged (final int) but now floored.
- Consumes: `_precondition_cap(list[str])` from Task 1.

- [ ] **Step 1: Write the failing test** (the exact O-031 invariant):

```python
def _sev(id_, sev, cvss, preconds):
    from sec_harness.models import Finding, FindingStatus
    return Finding(id=id_, rule_id="r", cls="authz", status=FindingStatus.CONFIRMED,
                   severity=sev, file="a.py", line=1, message="m",
                   cvss_vector=cvss, preconditions=preconds)


def test_critical_never_ranks_below_medium():
    # O-031: NoSQL-ATO critical (3 free preconds) must outrank a committed-secret medium.
    from sec_harness.models import Severity
    crit = _sev("C-CRIT", Severity.CRITICAL, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                ["unauthenticated", "extended query parsing", "route wiring"])
    med = _sev("C-MED", Severity.MEDIUM, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
               ["secret is live/unrotated"])
    assert calibrate_score(crit) >= 8            # severity floor for critical
    assert calibrate_score(crit) > calibrate_score(med)


def test_severity_floor_values():
    from sec_harness.calibrate import _severity_floor
    from sec_harness.models import Severity
    assert _severity_floor(Severity.CRITICAL) == 8
    assert _severity_floor(Severity.HIGH) == 6
    assert _severity_floor(Severity.MEDIUM) == 4
    assert _severity_floor(Severity.LOW) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_calibrate.py::test_critical_never_ranks_below_medium tests/test_calibrate.py::test_severity_floor_values -v`
Expected: FAIL (`_severity_floor` undefined; critical currently caps to 5 < medium 8).

- [ ] **Step 3: Write minimal implementation** — add to `calibrate.py`:

```python
# Severity floor: risk_score must never invert severity ordering (fixes O-031). A medium can
# reach 8 via CVSS (C:L/I:H), so a critical must floor at 8. The floor is applied for ORDERING;
# the inflation flag (advisory) compares against the pre-floor derived score so disagreement is
# still surfaced.
_SEVERITY_FLOOR = {"critical": 8, "high": 6, "medium": 4, "low": 2, "info": 1}


def _severity_floor(severity) -> int:
    """Minimum risk_score implied by the severity band."""
    return _SEVERITY_FLOOR.get(severity.value, 1)
```

Refactor `calibrate_score` so the pre-floor score is reusable, then floor it (baseline cap wins last):

```python
def _derived_score(finding: Finding) -> int:
    """Pre-floor score: CVSS/heuristic then precondition cap (NO severity floor)."""
    raw = None
    if finding.cvss_vector:
        try:
            raw = max(1, min(10, round(cvss31_base(finding.cvss_vector)[0])))
        except ValueError:
            raw = None
    if raw is None:
        raw = _heuristic_score(finding)
    return min(raw, _precondition_cap(finding.preconditions))


def calibrate_score(finding: Finding) -> int:
    """Compute the 1-10 risk score: derived score, floored by severity, then baseline cap.

    Args:
        finding: The finding to score.

    Returns:
        Int in ``[1, 10]``. Severity floor prevents rank inversion; an industry-standard-safe
        finding is still capped low (baseline cap applied last).
    """
    raw = max(_derived_score(finding), _severity_floor(finding.severity))
    if _is_baseline_standard(finding):
        raw = min(raw, _BASELINE_CAP)
    return raw
```

Update `calibrate_findings` so inflation compares claimed severity against the **pre-floor** score:

```python
            f.risk_score = calibrate_score(f)
            delta = inflation_delta(f, _derived_score(f))  # pre-floor: floor must not mask inflation
```

- [ ] **Step 4: Finalize the pre-existing precondition/inflation tests**

Finalize `test_precondition_cap_lowers_score`'s third assertion to `== 8` (floored). Replace `test_inflation_flag_recorded` so inflation is driven by the pre-floor derived score:

```python
def test_inflation_flag_recorded(tmp_path):
    # CRITICAL claimed (base 9) but strong preconditions derive a pre-floor score of 5 -> delta 4;
    # risk_score is floored to 8 for ordering, but the inflation advisory still fires off pre-floor.
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [_crit("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                              ["requires admin token", "non-default config", "local access"])])
    calibrate_findings(ws)
    f = read_findings(ws)[0]
    assert f.risk_score == 8                       # floored (ordering)
    events = [h for h in f.history if h.get("event") == "calibrate:severity-inflated"]
    assert len(events) == 1 and events[0]["delta"] == 4   # 9 (claimed) - 5 (pre-floor derived)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_calibrate.py -v`
Expected: ALL pass (including `test_calibrate_uses_cvss_vector_when_present` == 10 and `test_calibrate_malformed_vector_falls_back` == 3 — a LOW with garbage vector: heuristic 3, floor(low)=2, so `max(3,2)=3`, unchanged).

- [ ] **Step 6: Lint**

Run: `uv run ruff check sec_harness/calibrate.py tests/test_calibrate.py && uv run ty check`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/calibrate.py skills/sec-harness/helpers/tests/test_calibrate.py
git commit -m "fix(calibrate): weight preconditions by difficulty + severity floor (O-031)"
```

---

### Task 3: Disposition-aware red-team action bar

**Files:**
- Modify: `helpers/sec_harness/redteam.py` (`discriminate`; add `_above_bar`)
- Test: `helpers/tests/test_redteam.py`

**Interfaces:**
- Produces: `_above_bar(f: Finding, min_risk: int) -> bool`.
- Consumes: `wants_runtime(f)`, `Finding`, `Severity` (already imported / import `Severity`).

- [ ] **Step 1: Write the failing test** — add to `test_redteam.py`:

```python
def _rt(id_, sev, risk, disp="needs-runtime", status=None):
    from sec_harness.models import Finding, FindingStatus
    return Finding(id=id_, rule_id="r", cls="authz",
                   status=status or FindingStatus.CONFIRMED, severity=sev,
                   file="a.py", line=1, message="m", risk_score=risk,
                   runtime_disposition=disp)


def test_confirmed_high_severity_needs_runtime_is_actionable_below_min_risk():
    from sec_harness.redteam import discriminate
    from sec_harness.models import Severity
    # critical needs-runtime with risk 5 (below the 7 bar) MUST still be a directive (O-016/O-031).
    crit = _rt("A-1", Severity.CRITICAL, 5)
    disc = discriminate([crit], min_risk=7)
    assert [f.id for f in disc["needs_runtime"]] == ["A-1"]
    assert disc["below_bar"] == []


def test_low_severity_needs_runtime_gated_by_min_risk():
    from sec_harness.redteam import discriminate
    from sec_harness.models import Severity
    low = _rt("A-2", Severity.LOW, 4)
    disc = discriminate([low], min_risk=7)
    assert [f.id for f in disc["below_bar"]] == ["A-2"]
    assert disc["needs_runtime"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_redteam.py::test_confirmed_high_severity_needs_runtime_is_actionable_below_min_risk -v`
Expected: FAIL (critical at risk 5 currently lands in `below_bar`).

- [ ] **Step 3: Write minimal implementation** — in `redteam.py`, add the import and helper, and use it in `discriminate`:

```python
from sec_harness.models import Finding, FindingStatus, Severity  # add Severity

_ACTIONABLE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def _above_bar(f: Finding, min_risk: int) -> bool:
    """A needs-runtime finding is actionable if its severity is >= medium, else gated by min_risk.

    Fixes O-016/O-031: min_risk can no longer hide a confirmed critical/high whose deterministic
    risk_score sits low.
    """
    if f.severity in _ACTIONABLE_SEVERITIES:
        return True
    return (f.risk_score or 0) >= min_risk
```

Change the branch in `discriminate` from
`(plan if (f.risk_score or 0) >= min_risk else below_bar).append(f)` to:

```python
            (plan if _above_bar(f, min_risk) else below_bar).append(f)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_redteam.py -v`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `uv run ruff check sec_harness/redteam.py tests/test_redteam.py && uv run ty check`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/redteam.py skills/sec-harness/helpers/tests/test_redteam.py
git commit -m "fix(redteam): disposition-aware action bar so min-risk can't hide criticals (O-016)"
```

---

### Task 4: Cluster acceptance — end-to-end ordering invariant

**Files:**
- Test: `helpers/tests/test_calibrate.py` (integration test; no new source)

**Interfaces:**
- Consumes: `calibrate_findings`, `discriminate`.

- [ ] **Step 1: Write the acceptance test** (reproduces the coterie-backend O-031 scenario):

```python
def test_cluster_a_acceptance_ordering(tmp_path):
    """A confirmed critical needs-runtime finding outranks a medium AND enters the plan."""
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.redteam import discriminate
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    crit = Finding(id="AUTHZ-0001", rule_id="r", cls="authz",
                   status=FindingStatus.CONFIRMED, severity=Severity.CRITICAL,
                   file="orders.js", line=87, message="unauth order cancel",
                   cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H",
                   preconditions=["unauthenticated", "knows order id"],
                   runtime_disposition="needs-runtime")
    med = Finding(id="SECRETS-0002", rule_id="r", cls="secrets",
                  status=FindingStatus.CONFIRMED, severity=Severity.MEDIUM,
                  file=".env.example", line=23, message="committed secret",
                  cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
                  preconditions=["secret is live"], runtime_disposition="needs-runtime")
    write_findings(ws, [crit, med])
    calibrate_findings(ws)
    scored = {f.id: f.risk_score for f in read_findings(ws)}
    assert scored["AUTHZ-0001"] >= scored["SECRETS-0002"]   # critical never below medium
    assert scored["AUTHZ-0001"] >= 8
    disc = discriminate(read_findings(ws), min_risk=7)
    assert "AUTHZ-0001" == disc["needs_runtime"][0].id       # critical ranks first in the plan
```

- [ ] **Step 2: Run to verify it passes** (Tasks 1-3 already implemented)

Run: `uv run pytest tests/test_calibrate.py::test_cluster_a_acceptance_ordering -v`
Expected: PASS.

- [ ] **Step 3: Full suite + lint**

Run: `uv run pytest -q && uv run ruff check sec_harness/ tests/ && uv run ty check`
Expected: green (aside from the 2 known env-only failures documented in CLAUDE.md §2).

- [ ] **Step 4: Commit**

```bash
git add skills/sec-harness/helpers/tests/test_calibrate.py
git commit -m "test(calibrate): lock cluster-A prioritization ordering invariant (O-031)"
```

---

## Self-review notes

- **Spec coverage:** GSD Cluster A's 3 changes → Tasks 1 (difficulty weight), 2 (severity floor + pre-floor inflation), 3 (disposition bar); Task 4 locks the acceptance criterion. ✓
- **Type consistency:** `_precondition_cap` signature changes `(int)->(list[str])` — the only call site (`calibrate_score`) is updated in Task 1. `_derived_score` introduced in Task 2 and reused by `calibrate_findings`. `_above_bar` used only in `discriminate`. ✓
- **Existing-test impact:** `test_precondition_cap_lowers_score` and `test_inflation_flag_recorded` encoded the O-031 bug and are rewritten (Tasks 1/2) — flagged explicitly, values computed, not hand-waved. ✓
- **Non-goals:** no change to CVSS math, the read-only invariant, or the report format (Cluster G).

## After Cluster A
The remaining clusters (F/T7, B, C, E, D, G) each get their own plan in `docs/plans/` when A lands. F/T7 is next (calibrate crash: `cvss31_base` raises `KeyError` on an invalid metric while `calibrate_score` only catches `ValueError`).
