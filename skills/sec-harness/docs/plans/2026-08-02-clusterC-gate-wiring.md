# Cluster C — Phase-Adversary Gate Wiring (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Make the phase-adversary gate reviewable — the gate record must carry each claim's text + refs, and there must be a shared extractor that turns a phase artifact into `{id, text, refs}` claims, so the opus adversary reviews concrete claims instead of opaque ids.

**Architecture:** `GateDecision` carries `refs` + `text` (populated by `run_phase_checks` from the input claims) so `build_gate_record`'s `decisions` list serializes claim content; `build_gate_record` adds a `claims` map (`id → {text, refs}`) for the sent-to-adversary set. Extractors `claims_from_profile` / `claims_from_context` produce the `{id, text, refs}` claim lists. The `phase-adversary.md` prompt reads claim content from the record.

**Tech Stack:** Python 3.13 stdlib-only, pytest/ruff/ty. Run from `skills/sec-harness/helpers/`.

## Global Constraints
- stdlib-only; line 100; ruff+ty clean on changed files.
- Backward compatible: existing callers of `build_gate_record`/`run_phase_checks` keep working (new fields default-populated).
- Evidence: O-004 (gate record stored opaque claim_ids; adversary had nothing to review; the repo-1 win happened despite this via the prompt's "re-derive from code").
- Branch `skill-audit-driver-20260731`; stage only `skills/` paths; never `git add -A`.

---

### Task 1: GateDecision + record carry claim content

**Files:** Modify `helpers/sec_harness/phase_gate.py` (`GateDecision`, `run_phase_checks`, `build_gate_record`). Test: `helpers/tests/test_phase_gate.py`.

- [ ] **Step 1: failing test** (add to test_phase_gate.py):
```python
def test_gate_decision_and_record_carry_claim_content(tmp_path):
    from sec_harness.phase_gate import run_phase_checks, build_gate_record
    (tmp_path / "a.py").write_text("x = 1\n")
    claims = [{"id": "ep-0", "text": "entrypoint handler foo", "refs": ["a.py"]},
              {"id": "ep-1", "text": "missing thing", "refs": ["nope.py"]}]
    decs = run_phase_checks(claims, tmp_path)
    d0 = {d.claim_id: d for d in decs}["ep-0"]
    assert d0.refs == ["a.py"] and d0.text == "entrypoint handler foo"
    rec = build_gate_record("recon", decs)
    # the sent-to-adversary claim's text+refs are recoverable from the record (O-004)
    assert rec["claims"]["ep-0"] == {"text": "entrypoint handler foo", "refs": ["a.py"]}
    assert rec["decisions"][0]["text"] == "entrypoint handler foo"
```
- [ ] **Step 2: run, expect FAIL** — `uv run pytest tests/test_phase_gate.py::test_gate_decision_and_record_carry_claim_content -v` (GateDecision has no `refs`/`text`; record has no `claims`).
- [ ] **Step 3: implement** — in phase_gate.py:
  - Add fields to the dataclass: `refs: list[str] = field(default_factory=list)` and `text: str = ""` (after `reasons`).
  - In `run_phase_checks`, when constructing each `GateDecision`, pass `refs=list(refs)` and `text=str(claim.get("text", ""))`. (`refs` is already computed as `claim.get("refs", [])`.)
  - In `build_gate_record`, add a `claims` map built from the to-adversary decisions:
    ```python
        claims = {d.claim_id: {"text": d.text, "refs": d.refs}
                  for d in decisions if d.status == "to-adversary"}
        ```
    and add `"claims": claims,` to the returned dict.
- [ ] **Step 4: run PASS**; full `uv run pytest tests/test_phase_gate.py -q` (existing gate tests must still pass — the new fields default, so `build_gate_record`'s other keys are unchanged).
- [ ] **Step 5: lint** — `uv run ruff check sec_harness/phase_gate.py tests/test_phase_gate.py && uv run ty check sec_harness/phase_gate.py`.
- [ ] **Step 6: commit** — `git add skills/sec-harness/helpers/sec_harness/phase_gate.py skills/sec-harness/helpers/tests/test_phase_gate.py && git commit -m "feat(phase_gate): gate record carries claim text+refs (O-004)"`

---

### Task 2: claim extractors (profile + context)

**Files:** Modify `helpers/sec_harness/phase_gate.py` (add `claims_from_profile`, `claims_from_context`). Test: `helpers/tests/test_phase_gate.py`.

**Interfaces:** `claims_from_profile(profile) -> list[dict]`, `claims_from_context(ctx) -> list[dict]`, each a list of `{"id": str, "text": str, "refs": list[str]}`.

- [ ] **Step 0: verify model field names first** — before writing, read the `ScanProfile` fields (`entrypoints`, `subsystems`) and the `Context`/`ContextItem` fields (how items are stored + the attribute holding the code location, e.g. `where`, and the summary/text attribute). Run:
  `uv run python -c "from sec_harness.profile import load_profile; import inspect"` and inspect `sec_harness.context` for the Context/ContextItem shape. Adapt the attribute access in Step 3 to the real names.
- [ ] **Step 1: failing test**:
```python
def test_claims_from_profile_extracts_entrypoints_and_subsystems():
    from sec_harness.phase_gate import claims_from_profile
    class P:  # minimal stand-in matching ScanProfile's attributes used here
        entrypoints = ["src/app.py:handler", "src/api.py:route"]
        subsystems = [{"name": "auth", "paths": ["src/auth.py"], "why": "login"}]
    claims = claims_from_profile(P())
    ids = {c["id"] for c in claims}
    assert "ep-0" in ids and any(c["id"].startswith("sub-0") for c in claims)
    ep0 = next(c for c in claims if c["id"] == "ep-0")
    assert ep0["refs"] == ["src/app.py"]           # path before the ':symbol'
    sub = next(c for c in claims if c["id"].startswith("sub-0"))
    assert sub["refs"] == ["src/auth.py"]
```
- [ ] **Step 2: run, expect FAIL**.
- [ ] **Step 3: implement** `claims_from_profile` (and `claims_from_context`, adapting to the real ContextItem fields verified in Step 0):
```python
def claims_from_profile(profile) -> list[dict]:
    """Turn a recon ScanProfile into gate claims (one per entrypoint + subsystem)."""
    claims: list[dict] = []
    for i, ep in enumerate(getattr(profile, "entrypoints", []) or []):
        ref = ep.split(":")[0] if isinstance(ep, str) else str(ep)
        claims.append({"id": f"ep-{i}", "text": f"entrypoint {ep}",
                       "refs": [ref] if ref else []})
    for i, s in enumerate(getattr(profile, "subsystems", []) or []):
        name = s.get("name", f"sub-{i}")
        claims.append({"id": f"sub-{i}:{name}",
                       "text": f"subsystem {name}: {s.get('why', '')}",
                       "refs": list(s.get("paths", []))})
    return claims


def claims_from_context(ctx) -> list[dict]:
    """Turn an ingested Context into gate claims (one per item with a code location)."""
    claims: list[dict] = []
    items = getattr(ctx, "items", None) or (ctx.get("items", []) if isinstance(ctx, dict) else [])
    for i, it in enumerate(items):
        get = it.get if isinstance(it, dict) else (lambda k, d=None: getattr(it, k, d))
        where = get("where", "") or ""
        kind = get("kind", None) or get("type", "item")
        summary = get("summary", "") or get("note", "") or get("desc", "")
        claims.append({"id": f"ctx-{i}", "text": f"{kind}: {summary}".strip(),
                       "refs": [where] if where else []})
    return claims
```
- [ ] **Step 4: run PASS**; **Step 5: lint**; **Step 6: commit** — `git commit -m "feat(phase_gate): claims_from_profile/context extractors (O-004)"` (stage phase_gate.py + test).

---

### Task 3: phase-adversary prompt reads claim content

**Files:** Modify `skills/sec-harness/agents/phase-adversary.md`. No test (prose).

- [ ] **Step 1: edit** — in the Inputs / Procedure section, replace the guidance that references reviewing "the sent_to_adversary claims" with content-aware guidance:
  "Read `kb/gates/{{PHASE}}.json`: the `claims` map gives each sent-to-adversary claim's `text` + `refs`, and `decisions[]` carries the same per claim. Your verdict table has one row per entry in `claims` (or per `sent_to_adversary` id). For each, re-derive the claim from its `refs` in code (Read/ast-grep) — do NOT trust the claim text; it is the producer's assertion to challenge."
- [ ] **Step 2: verify** — `grep -n "claims" skills/sec-harness/agents/phase-adversary.md`.
- [ ] **Step 3: commit** — `git add skills/sec-harness/agents/phase-adversary.md && git commit -m "docs(phase-adversary): review claims by content from the gate record (O-004)"`

---

## Self-review
- Spec coverage: GSD Cluster C → Task 1 (persist claim content), Task 2 (extractors), Task 3 (prompt). ✓
- Backward compat: new GateDecision fields default; existing record keys unchanged + `claims` added. ✓
- Type consistency: `claims_from_profile/context -> list[dict]`; GateDecision.`refs: list[str]`, `.text: str`. ✓
- Note: `claims_from_architecture` (prose) deferred — profile + context are the structured, high-value gated phases; architecture claims can reuse `claims_from_context`-style extraction in a follow-up.
