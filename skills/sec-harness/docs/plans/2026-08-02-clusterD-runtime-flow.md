# Cluster D — needs-runtime Status Flow (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** A finding that is real-but-only-provable-live must reach the red-team plan automatically, instead of dying as a weak `raw`/`verify-error` that `redteam.discriminate` skips.

**Architecture:** A `runtime_dependent: bool` marker on `Finding` (set by investigate/validate when the only blocker to confirmation is data not in the repo). A deterministic `campaign.promote_runtime_dependent(ws)` promotes such findings to `needs-deployment-testing` (which `redteam.discriminate` already admits). Prompts set the marker.

**Tech Stack:** Python 3.13 stdlib-only, pytest/ruff/ty. Run from `skills/sec-harness/helpers/`.

## Global Constraints
- stdlib-only; line 100; ruff+ty clean on changed files.
- Non-destructive + recall-safe: promotion only affects findings explicitly marked `runtime_dependent`.
- Evidence: O-010 (needs-deployment-testing unavailable at investigate stage), O-021 (verify-error runtime-only findings never reach the plan; had to be promoted by hand on repo 1).
- Branch `skill-audit-driver-20260731`; stage only `skills/` paths; never `git add -A`.

---

### Task 1: Finding.runtime_dependent marker

**Files:** Modify `helpers/sec_harness/models.py` (add field). Test: `helpers/tests/test_models.py`.

- [ ] **Step 1: failing test**:
```python
def test_runtime_dependent_field_roundtrips_and_defaults_false():
    from sec_harness.models import Finding, FindingStatus, Severity
    f = Finding(id="F-1", rule_id="r", cls="business-logic", status=FindingStatus.RAW,
                severity=Severity.LOW, file="a.py", line=1, message="m")
    assert f.runtime_dependent is False
    f.runtime_dependent = True
    assert Finding.from_dict(f.to_dict()).runtime_dependent is True
```
- [ ] **Step 2: run FAIL** (no such field).
- [ ] **Step 3: implement** — add to the `Finding` dataclass field list (with the other defaulted fields): `runtime_dependent: bool = False`. `to_dict` (asdict) and `from_dict` (known-key filter) handle it automatically — no other change.
- [ ] **Step 4: run PASS**; full `uv run pytest tests/test_models.py -q`.
- [ ] **Step 5: lint** models.py + test.
- [ ] **Step 6: commit** — `git add skills/sec-harness/helpers/sec_harness/models.py skills/sec-harness/helpers/tests/test_models.py && git commit -m "feat(models): runtime_dependent marker for runtime-only findings (O-010)"`

---

### Task 2: campaign.promote_runtime_dependent

**Files:** Modify `helpers/sec_harness/campaign.py` (add function). Test: `helpers/tests/test_campaign.py`.

**Interfaces:** `promote_runtime_dependent(ws: Workspace) -> int` — sets any `RAW`-status finding with `runtime_dependent is True` to `NEEDS_DEPLOYMENT_TESTING`, appends a history event, writes findings, returns the count.

- [ ] **Step 1: failing test**:
```python
def test_promote_runtime_dependent(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.workspace import Workspace, read_findings, write_findings
    from sec_harness.campaign import promote_runtime_dependent
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    def f(id_, rd, status=FindingStatus.RAW):
        return Finding(id=id_, rule_id="r", cls="business-logic", status=status,
                       severity=Severity.LOW, file="a.py", line=1, message="m",
                       runtime_dependent=rd)
    write_findings(ws, [f("A", True), f("B", False), f("C", True, FindingStatus.CONFIRMED)])
    assert promote_runtime_dependent(ws) == 1                       # only the raw+rd one
    by = {x.id: x.status for x in read_findings(ws)}
    assert by["A"] is FindingStatus.NEEDS_DEPLOYMENT_TESTING
    assert by["B"] is FindingStatus.RAW                             # not marked -> untouched
    assert by["C"] is FindingStatus.CONFIRMED                       # already terminal -> untouched
```
- [ ] **Step 2: run FAIL**.
- [ ] **Step 3: implement** — add to campaign.py (check `read_findings`/`write_findings`/`FindingStatus` imports; add if missing):
```python
def promote_runtime_dependent(ws: Workspace) -> int:
    """Promote raw findings marked runtime_dependent to needs-deployment-testing (O-010/O-021).

    A finding whose only barrier to confirmation is data not in the repo (catalog, live host,
    secret liveness) is a genuine runtime lead — it must reach the red-team plan, not die as raw.
    """
    findings = read_findings(ws)
    n = 0
    for f in findings:
        if f.status is FindingStatus.RAW and f.runtime_dependent:
            f.status = FindingStatus.NEEDS_DEPLOYMENT_TESTING
            f.history.append({"event": "campaign:promoted-runtime-dependent"})
            n += 1
    if n:
        write_findings(ws, findings)
    return n
```
- [ ] **Step 4: run PASS**; **Step 5: lint** campaign.py + test.
- [ ] **Step 6: commit** — `git commit -m "feat(campaign): promote_runtime_dependent -> needs-deployment-testing (O-021)"` (stage campaign.py + test).

---

### Task 3: prompts set the marker + SKILL wires the step

**Files:** Modify `skills/sec-harness/agents/investigate.md`, `skills/sec-harness/agents/validate.md`, `skills/sec-harness/SKILL.md`. No test (prose).

- [ ] **Step 1: investigate.md** — in the Decide/Output rules, add: "If a finding is real in code but its exploitability can only be settled with data NOT in the repo (catalog contents, a live host, whether a committed secret is live), set `runtime_dependent: true` on the finding (keep `status: raw`). Do not force it to a confident `raw` or drop it — the marker routes it to the runtime plan."
- [ ] **Step 2: validate.md** — in the Verify-error guidance, add: "When you cannot confirm because the missing evidence is runtime/external data (not a code control you could cite), set `verification: verify-error` AND `runtime_dependent: true` — it will be promoted to needs-deployment-testing for the red-team plan, not silently dropped."
- [ ] **Step 3: SKILL.md** — in Phase 5.5 (Red Team), before the red-team agent step, add: "First run `promote_runtime_dependent(ws)` (from `sec_harness.campaign`) so raw findings marked `runtime_dependent` become `needs-deployment-testing` and enter the plan (O-021)."
- [ ] **Step 4: commit** — `git add skills/sec-harness/agents/investigate.md skills/sec-harness/agents/validate.md skills/sec-harness/SKILL.md && git commit -m "docs(sec-harness): agents set runtime_dependent; SKILL promotes it pre-redteam (O-021)"`

---

## Self-review
- Spec coverage: GSD Cluster D → Task 1 (marker), 2 (promote step), 3 (prompts + wiring). ✓
- redteam.discriminate already admits needs-deployment-testing (verified in redteam.py `is_ndt`), so promoted findings flow to the plan. ✓
- Recall-safe: only RAW + runtime_dependent promoted; terminal findings untouched. ✓
- Type consistency: `Finding.runtime_dependent: bool`, `promote_runtime_dependent(ws) -> int`. ✓
