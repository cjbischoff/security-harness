# Cluster F / T7 — Calibrate crash on malformed CVSS (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** One malformed CVSS vector (`C:M`) must never crash risk calibration for a whole workspace.

**Architecture:** `cvss31_base` raises `ValueError` (not `KeyError`) on any invalid/missing metric, so the existing `except ValueError` in `calibrate._derived_score` falls back to the heuristic. Add per-finding isolation in `calibrate_findings` (defense-in-depth). List legal CVSS metric values in the severity prompt so the LLM stops emitting them.

**Tech Stack:** Python 3.13, stdlib-only, pytest/ruff/ty. Run from `skills/sec-harness/helpers/`.

## Global Constraints
- stdlib-only; line length 100; ruff+ty clean on changed files.
- Non-destructive: a bad CVSS vector falls back to the heuristic score; it must NOT drop the finding.
- Evidence: O-029 (coterie-backend: `C:M` → `KeyError: 'M'` zeroed all 24 findings' risk_score).
- Branch `skill-audit-driver-20260731`; stage only `skills/` paths; never `git add -A`.

---

### Task 1: cvss31_base raises ValueError on invalid/missing metric

**Files:** Modify `helpers/sec_harness/cvss.py` (`cvss31_base`). Test: `helpers/tests/test_cvss.py` (create if absent).

- [ ] **Step 1: failing test**
```python
import pytest
from sec_harness.cvss import cvss31_base

def test_invalid_metric_value_raises_valueerror():
    # 'M' is not a legal Confidentiality value (N/L/H) — must be ValueError, not KeyError (O-029).
    with pytest.raises(ValueError):
        cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:H/A:N")

def test_valid_vector_still_scores():
    score, rating = cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert round(score) == 10
```
- [ ] **Step 2: run, expect FAIL** — `uv run pytest tests/test_cvss.py -v` (first test raises KeyError, not ValueError).
- [ ] **Step 3: implement** — in `cvss31_base`, wrap the metric-dependent computation so a missing/invalid metric becomes a ValueError. Immediately after `m = _parse(vector)`:
```python
    try:
        scope_changed = m["S"] == "C"
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    except KeyError as e:
        raise ValueError(f"invalid or missing CVSS 3.1 metric {e}") from e
```
(Keep the rest of the function — `impact`/`raw`/`score` — unchanged, after this block.)
- [ ] **Step 4: run, expect PASS** — `uv run pytest tests/test_cvss.py -v`.
- [ ] **Step 5: lint** — `uv run ruff check sec_harness/cvss.py tests/test_cvss.py && uv run ty check sec_harness/cvss.py`.
- [ ] **Step 6: commit** — `git add skills/sec-harness/helpers/sec_harness/cvss.py skills/sec-harness/helpers/tests/test_cvss.py && git commit -m "fix(cvss): raise ValueError not KeyError on invalid metric (O-029)"`

---

### Task 2: calibrate falls back + isolates per-finding failures

**Files:** Modify `helpers/sec_harness/calibrate.py` (`calibrate_findings`). Test: `helpers/tests/test_calibrate.py`.

**Interfaces:** Consumes Task 1's `cvss31_base` ValueError behavior. `calibrate_score` already catches ValueError → heuristic.

- [ ] **Step 1: failing test** (add to `test_calibrate.py`):
```python
def test_malformed_cvss_does_not_crash_batch(tmp_path):
    # O-029: one finding with an invalid metric must NOT zero the others; it falls back to heuristic.
    from sec_harness.models import Finding, FindingStatus, Severity
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    good = Finding(id="G", rule_id="r", cls="sqli", status=FindingStatus.CONFIRMED,
                   severity=Severity.HIGH, file="a.py", line=1, message="m",
                   dataflow=["a @ x:1", "-> b @ x:2"])
    bad = Finding(id="B", rule_id="r", cls="secrets", status=FindingStatus.CONFIRMED,
                  severity=Severity.MEDIUM, file="a.py", line=2, message="m",
                  cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:H/A:N")
    write_findings(ws, [good, bad])
    n = calibrate_findings(ws)                 # must not raise
    assert n == 2
    by_id = {f.id: f for f in read_findings(ws)}
    assert by_id["G"].risk_score == 9          # good finding scored normally
    assert by_id["B"].risk_score is not None    # bad-vector finding fell back to heuristic, not crash
```
- [ ] **Step 2: run, expect PASS ALREADY** if Task 1 landed (calibrate_score catches ValueError). Run `uv run pytest tests/test_calibrate.py::test_malformed_cvss_does_not_crash_batch -v`. If it PASSES, the Task-1 fix already covers the batch case — proceed to add defense-in-depth isolation anyway (Step 3) so any FUTURE non-ValueError error can't crash the batch.
- [ ] **Step 3: implement isolation** — in `calibrate_findings`, wrap the per-finding scoring body in try/except so an unexpected error logs + leaves `risk_score=None` for that finding but continues the loop:
```python
    for f in findings:
        if f.status is FindingStatus.CONFIRMED:
            try:
                _attach_citations(f)
                derived = _derived_score(f)
                f.risk_score = max(derived, _severity_floor(f.severity))
                if _is_baseline_standard(f):
                    f.risk_score = min(f.risk_score, _BASELINE_CAP)
                delta = inflation_delta(f, derived)
                if delta >= _INFLATION_THRESHOLD and not any(
                    h.get("event") == "calibrate:severity-inflated" for h in f.history
                ):
                    f.history.append({"event": "calibrate:severity-inflated",
                                      "claimed": f.severity.value, "derived": derived, "delta": delta})
                if f.cvss_vector:
                    try:
                        f.priority = offensive_priority(f.cvss_vector)
                    except ValueError:
                        pass
            except Exception as exc:  # noqa: BLE001 — per-finding isolation; one bad finding must not zero the batch
                f.history.append({"event": "calibrate:error", "error": str(exc)})
            scored += 1
```
(This inlines `calibrate_score`'s body so the isolation covers the whole per-finding computation. `calibrate_score` stays as the public single-finding entry point — do not delete it.)
- [ ] **Step 4: run** — `uv run pytest tests/test_calibrate.py -v` all green (existing cluster-A tests included).
- [ ] **Step 5: lint** — `uv run ruff check sec_harness/calibrate.py tests/test_calibrate.py && uv run ty check sec_harness/calibrate.py`.
- [ ] **Step 6: commit** — `git add skills/sec-harness/helpers/sec_harness/calibrate.py skills/sec-harness/helpers/tests/test_calibrate.py && git commit -m "fix(calibrate): isolate per-finding scoring failures (O-029)"`

---

### Task 3: Prompt lists legal CVSS metric values

**Files:** Modify `skills/sec-harness/references/prompt-constants.md` (SEVERITY_GUIDANCE block). No test (prose).

- [ ] **Step 1: edit** — in the `## SEVERITY_GUIDANCE` block, after the CVSS sentence, add:
```
Legal CVSS 3.1 base-metric values (use ONLY these): AV:[N,A,L,P] AC:[L,H] PR:[N,L,H] UI:[N,R]
S:[U,C] C:[N,L,H] I:[N,L,H] A:[N,L,H]. Never emit a value outside these sets (e.g. `C:M` is invalid).
```
- [ ] **Step 2: verify** — `grep -n "Legal CVSS" skills/sec-harness/references/prompt-constants.md`.
- [ ] **Step 3: commit** — `git add skills/sec-harness/references/prompt-constants.md && git commit -m "docs(prompts): enumerate legal CVSS metric values so agents can't emit C:M (O-029)"`

---

## Self-review
- Spec coverage: GSD F/T7 → Task 1 (root-cause ValueError), Task 2 (batch survival + isolation), Task 3 (prevent bad input). ✓
- Non-destructive: bad vector → heuristic, finding kept. ✓
- Type consistency: no signature changes; `calibrate_score` retained. Task 2 inlines its body into `calibrate_findings` with isolation — behavior identical for valid findings (existing cluster-A tests still assert exact scores). ✓
