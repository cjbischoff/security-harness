# sec-harness QA Batched-Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 22 batched QA issues logged during the 3-run dogfood (`docs/dogfooding/runtime-issues_20260803.md`), fixing recall-capping bugs, gate-coverage gaps, and prompt/doc defects without touching the frozen Go contract.

**Architecture:** Fixes are grouped by subsystem. Deterministic code changes are TDD (failing test first) and stdlib-only. Agent-prompt and reference-doc changes preserve every load-bearing hard rule verbatim. Two issues near the contract (013, 019) are solved at the report/redteam presentation layer only.

**Tech Stack:** Python 3.13 (stdlib-only core), `uv run pytest`, `ruff`, `ty`. Agent prompts are Markdown under `agents/` and `references/`.

## Global Constraints

- **Go-safe, absolute:** NEVER edit `helpers/sec_harness/models.py` or `helpers/sec_harness/evidence.py`. No new enum values, no `to_dict`/`from_dict` changes, no `_MECHANICAL` whitelist changes. These are byte-for-byte mirrored by the parallel Go port; changing them breaks its build.
- **Do not change `fingerprint()` identity** (`helpers/sec_harness/fingerprint.py`): its `rule_id|cls|enclosing-symbol` key is mirrored by Go (memory: fingerprint-anchor-go-parity). Dedupe fixes use grouping keys inside `dedupe.py`, never the fingerprint algorithm.
- **stdlib-only:** no new runtime dependencies in `pyproject.toml` (dev deps stay pytest/ruff/ty).
- **Line length 100.** Run `uv run ruff check sec_harness/ tests/` and `uv run ty check` before every commit; zero warnings.
- **TDD for code** (Python): failing test first, confirm RED, minimal GREEN, refactor. Not required for prose-only prompt/doc edits (tdd.md).
- **Preserve agent-prompt hard rules verbatim:** model-family diversity, the tool-receipt safety contract, count-invariant verdict tables, and the OUTPUT_WRITE_FALLBACK import lines are load-bearing — never reword or drop them.
- **Git boundary:** stage explicit `skills/sec-harness/...` paths only; never `git add -A`; never touch `go/`. Work on branch `skill-qa-batched-fixes-20260803`.
- All work is from `helpers/` for Python (`cd skills/sec-harness/helpers`) and from `skills/sec-harness/` for prompts/docs.

---

## Subsystem A — Agent prompts & reference docs (prose)

These are Markdown edits. No red-green cycle except A5 (adds a wiring test). Each ends with `ruff`/`ty` unaffected; verify the prompt still renders its hard-rule blocks.

### Task A1 — ISSUE-003: context-ingest handles thin structural docs

**Files:** Modify `agents/context-ingest.md`.

- [ ] **Step 1:** In the Procedure section, add one instruction: when repo docs are thin/structural (a directory tree, header comments, a bare README) rather than narrative, follow directory-comment breadcrumbs into the implementation files they name, and record those as `prior-scan`/`untrusted-doc` leads — do not treat absence of prose docs as "no context".
- [ ] **Step 2:** Verify the trust-envelope and import blocks are unchanged.
- [ ] **Step 3:** Commit: `git add skills/sec-harness/agents/context-ingest.md && git commit -m "fix(context-ingest): handle thin structural docs (ISSUE-003)"`

### Task A2 — ISSUE-004: recon references kb/context.json

**Files:** Modify `agents/recon.md`.

- [ ] **Step 1:** Add `{{WORKSPACE}}/kb/context.json` to recon's Inputs list, with one line: "C1 context leads (trust-tagged) inform — never override — evidence-based surface selection; a doc claim is not an indicator."
- [ ] **Step 2:** Confirm the reachability gate wording (recon.md:58-64) still governs `agents_to_spawn`.
- [ ] **Step 3:** Commit: `git commit -m "fix(recon): consume kb/context.json C1 leads (ISSUE-004)"`

### Task A3 — ISSUE-005: ai-agent hunting-doc class list is opt-in, not a bundle

**Files:** Modify `references/hunting/ai-agent.md`.

- [ ] **Step 1:** Reword the class list header so each class (`excessive-agency`, `denial-of-wallet`, `mcp-trust-inheritance`, `context-bleed`, `prompt-injection`) is selected only on its own evidence indicator — not inherited as a set. Explicitly note `mcp-trust-inheritance` requires a live MCP trust boundary in code, not merely the presence of an LLM.
- [ ] **Step 2:** Commit: `git commit -m "docs(hunting): ai-agent classes are per-evidence, not a bundle (ISSUE-005)"`

### Task A4 — ISSUE-007: recon symbol-existence discipline

**Files:** Modify `agents/recon.md`.

- [ ] **Step 1:** In the entrypoint-recording step (recon.md:34, `relative/path.ext:symbol_or_hint`), add: "Cite a symbol only if you have seen it in the file; if unsure, cite the file and a textual hint, never a guessed function name. A phantom symbol sends investigate to a line that does not exist." The phase gate resolves at file granularity, so this is a recall-quality rule the adversary enforces.
- [ ] **Step 2:** Commit: `git commit -m "fix(recon): forbid guessed symbol names in citations (ISSUE-007)"`

### Task A5 — ISSUE-010: class-extension map + missing files + wiring

**Files:**
- Create: `agents/classes/prompt-injection.md`, `agents/classes/excessive-agency.md`, `agents/classes/context-bleed.md`, `agents/classes/authn.md`, `agents/classes/ssrf.md`, `agents/classes/business-logic.md`
- Modify: `agents/investigate.md`, `agents/patch.md` (import the class extension)
- Create: `helpers/tests/test_class_extensions.py`

**Interfaces:**
- Produces: the convention `agents/classes/<attack_class>.md` exists for every class an orchestrator may dispatch; investigate/patch load `agents/classes/{{ATTACK_CLASS}}.md` when present.

- [ ] **Step 1 (RED):** Write `helpers/tests/test_class_extensions.py` asserting that for every class key in `references/attack-classes.md`'s selectable set that appears in a dispatchable `agents_to_spawn` (authz, authn, crypto, injection→sqli/cmdi mapped, config, resource, ssrf, prompt-injection, excessive-agency, context-bleed, business-logic), a file `agents/classes/<key>.md` exists and contains a `## Proof tuple` section.

```python
from pathlib import Path

CLASSES_DIR = Path(__file__).resolve().parents[1].parent / "agents" / "classes"
REQUIRED = {"authz", "authn", "crypto", "injection", "config", "resource",
            "ssrf", "prompt-injection", "excessive-agency", "context-bleed",
            "business-logic"}

def test_every_required_class_has_extension_with_proof_tuple():
    missing = [c for c in REQUIRED if not (CLASSES_DIR / f"{c}.md").exists()]
    assert not missing, f"missing class extensions: {missing}"
    for c in REQUIRED:
        text = (CLASSES_DIR / f"{c}.md").read_text()
        assert "## Proof tuple" in text, f"{c}.md lacks a Proof tuple section"
```

- [ ] **Step 2:** Run `uv run pytest tests/test_class_extensions.py -v` — expect FAIL (6 files missing).
- [ ] **Step 3:** Create the 6 files, each following the exact structure of `agents/classes/authz.md` (`# CWE-class extension — <class>`, `## Canonical fix shape`, `## Discrimination requirement`, `## Proof tuple (required evidence)` with three `file:line`-backed elements, `**Instance preservation:**` note). Content per class:
  - `prompt-injection.md`: tuple = (1) untrusted text reaching a model prompt, (2) model output flowing to a sink (exec/db/fetch/tool-call) without mediation, (3) attacker-controllable source.
  - `excessive-agency.md`: tuple = (1) an agent tool that performs a state change, (2) no per-call authz/confirmation re-check, (3) attacker influence over tool selection or args.
  - `context-bleed.md`: tuple = (1) shared context/memory across principals, (2) a read path returning another principal's data, (3) attacker-reachable trigger.
  - `authn.md`: tuple = (1) an identity/authentication decision point, (2) a bypass or weak-verification path, (3) unauthenticated/attacker reach.
  - `ssrf.md`: tuple = (1) a server-side request built from input, (2) no allowlist/SSRF guard on every path, (3) attacker-controlled destination.
  - `business-logic.md`: tuple = (1) an invariant the workflow must hold, (2) a state/step sequence that violates it, (3) attacker-reachable trigger.
- [ ] **Step 4 (GREEN):** Run the test — expect PASS.
- [ ] **Step 5:** In `agents/investigate.md` and `agents/patch.md` Imports section, add one line: "Also load the class extension `{{HARNESS_ROOT}}/agents/classes/{{ATTACK_CLASS}}.md` if it exists — it adds the proof tuple and canonical fix shape for this class." Preserve all existing import lines verbatim.
- [ ] **Step 6:** Commit: `git add skills/sec-harness/agents/classes/ skills/sec-harness/agents/investigate.md skills/sec-harness/agents/patch.md skills/sec-harness/helpers/tests/test_class_extensions.py && git commit -m "feat(classes): add 6 class extensions + wiring + test (ISSUE-010)"`

### Task A6 — ISSUE-014: investigate enumerates legal severity values

**Files:** Modify `agents/investigate.md`.

- [ ] **Step 1:** Where the finding write format is described, add: "severity MUST be one of exactly: `info`, `low`, `medium`, `high`, `critical`. `informational` is NOT valid and will crash the reader." (This was a real crash source, since patched in `read_findings`, but the prompt should not emit it.)
- [ ] **Step 2:** Commit: `git commit -m "fix(investigate): enumerate legal severity enum values (ISSUE-014)"`

### Task A7 — ISSUE-020: patch hardening

**Files:** Modify `agents/patch.md`.

- [ ] **Step 1:** Add to the patch procedure: (a) after producing a diff, mentally run `git apply --check` semantics — the `@@ -a,b +c,d @@` hunk line counts MUST match the actual added/removed line counts; miscount = a corrupt patch. (b) For multi-line diffs containing tabs or template literals, write the finding's `patch_diff` via the python-json injector (OUTPUT_WRITE_FALLBACK), never the Write tool, to avoid whitespace mangling.
- [ ] **Step 2:** Confirm the throwaway-copy-only rule and model-family lines are unchanged.
- [ ] **Step 3:** Commit: `git commit -m "fix(patch): mandate hunk-count check + json injector for diffs (ISSUE-020)"`

### Task A8 — ISSUE-024: attack-class catalog adds sandboxed-expression-evaluator RCE

**Files:** Modify `references/attack-classes.md`.

- [ ] **Step 1:** Add a row to the class table: key `expr-eval-rce`, name "Sandboxed expression/rule-engine escape", ripgrep indicators (`jsep`, `expr-eval`, `mathjs`, `vm.runInContext`, `callee.apply`, `constructor.constructor`, custom formula/rules engines), "static only". Add a one-line note distinguishing it from `deserialization` and `ssti`: the sink is a custom evaluator's own call/apply, not `eval()` or a template engine.
- [ ] **Step 2:** Commit: `git commit -m "docs(attack-classes): add expr-eval-rce class (ISSUE-024)"`

### Task A9 — ISSUE-025: recon authz factory-indirection

**Files:** Modify `agents/recon.md`.

- [ ] **Step 1:** In the authz-detection guidance, add: "When handler auth is applied via a factory/wrapper (e.g. `createBaseHandler`, a decorator, a base class), grepping the leaf handler for `apiToken`/`isInvalidToken` will miss it. Trace one level of wrapper indirection; if you cannot resolve it, record 'indirect auth dispatch — not verified' rather than emitting a false authz-gap lead."
- [ ] **Step 2:** Commit: `git commit -m "fix(recon): trace one hop of auth wrapper indirection (ISSUE-025)"`

---

## Subsystem B — Prefilter / classification

### Task B1 — ISSUE-011 (robust): high-sev unknown CodeQL → security-other

**Files:**
- Modify: `helpers/sec_harness/partition.py` (`demote_noise`, ~line 55-70)
- Test: `helpers/tests/test_partition.py`

**Interfaces:**
- Consumes: `Finding.severity`, `Finding.cls`, `FindingStatus` (read-only from frozen models).
- Produces: a high/critical `CANDIDATE` with `cls == "unknown"` is rerouted to `cls == "security-other"` and stays `CANDIDATE`; low/med `unknown` still demotes to `INFORMATIONAL`; `log-injection`/`clear-text-logging` demote regardless of severity (unchanged).

- [ ] **Step 1 (RED):** Add to `tests/test_partition.py`:

```python
def test_demote_noise_routes_high_severity_unknown_to_security_other(tmp_path):
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.partition import demote_noise
    from sec_harness.workspace import Workspace, read_findings, write_findings
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    f = Finding(id="C-1", rule_id="js/insufficient-password-hash", cls="unknown",
                status=FindingStatus.CANDIDATE, severity=Severity.HIGH,
                file="a.py", line=1, message="m")
    write_findings(ws, [f])
    demote_noise(ws)
    got = read_findings(ws)[0]
    assert got.status is FindingStatus.CANDIDATE      # not demoted
    assert got.cls == "security-other"                # rerouted
```

- [ ] **Step 2:** Run `uv run pytest tests/test_partition.py::test_demote_noise_routes_high_severity_unknown_to_security_other -v` — expect FAIL (status becomes INFORMATIONAL, cls stays unknown).
- [ ] **Step 3 (GREEN):** In `demote_noise`, before the `is_noise_class` demotion branch, add: if `f.status is FindingStatus.CANDIDATE and f.cls == "unknown" and f.severity in (Severity.HIGH, Severity.CRITICAL)`: set `f.cls = "security-other"`, append a history event `{"event": "partition:reroute-high-sev-unknown"}`, mark the finding dirty, and `continue` (skip demotion). Do not alter `clsmap.NOISE_CLASSES`.
- [ ] **Step 4:** Run the full `tests/test_partition.py` — expect PASS including the existing low-severity noise test.
- [ ] **Step 5:** `uv run ruff check sec_harness/ tests/ && uv run ty check`
- [ ] **Step 6:** Commit: `git add skills/sec-harness/helpers/sec_harness/partition.py skills/sec-harness/helpers/tests/test_partition.py && git commit -m "fix(partition): reroute high-sev unknown CodeQL to security-other (ISSUE-011)"`

---

## Subsystem C — structural_index

### Task C1 — ISSUE-012: index TS-typed const-arrow and class-field-arrow defs

**Files:**
- Modify: `helpers/sec_harness/structural_index.py` (regexes at lines 16-19; `list_definitions` tuple at ~line 35)
- Create: `helpers/tests/test_structural_index.py`

**Interfaces:**
- Produces: `list_definitions` returns typed `const` arrow bindings and class-field arrow bindings as definitions.

- [ ] **Step 1 (RED):** Create `helpers/tests/test_structural_index.py`:

```python
from sec_harness.structural_index import list_definitions

def test_list_definitions_finds_typed_const_arrow(tmp_path):
    p = tmp_path / "a.ts"
    p.write_text(
        "export const handler: RequestHandler = async (req, res) => {\n"
        "  return tool(req)\n"
        "}\n\nfunction tool(x) { return x }\n"
    )
    names = {n for n, _ in list_definitions(p)}
    assert "handler" in names

def test_list_definitions_finds_class_field_arrow(tmp_path):
    p = tmp_path / "b.js"
    p.write_text(
        "class Foo {\n  bar = () => {\n    return baz()\n  }\n}\n\n"
        "function baz() { return 1 }\n"
    )
    names = {n for n, _ in list_definitions(p)}
    assert "bar" in names
```

- [ ] **Step 2:** Run `uv run pytest tests/test_structural_index.py -v` — expect both FAIL.
- [ ] **Step 3 (GREEN):** Extend `_JS_ASSIGN` to allow an optional TS type annotation before `=`:
  `r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?\s*="`.
  Add `_JS_FIELD_ARROW = re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>")` and append it to the patterns tuple in `list_definitions`. Restrict the field pattern to arrow RHS so `x = 5` is not matched.
- [ ] **Step 4:** Run the test — expect PASS. Add a guard assertion (e.g. `x = 5` is NOT a def) inside the field-arrow test to prevent over-matching.
- [ ] **Step 5:** `ruff` + `ty`. Note in the commit body that the "single-hop caller resolution" part of ISSUE-012 is out of scope (an architectural limit of a ripgrep-backed index, not a bug).
- [ ] **Step 6:** Commit: `git add skills/sec-harness/helpers/sec_harness/structural_index.py skills/sec-harness/helpers/tests/test_structural_index.py && git commit -m "fix(structural-index): index typed/class-field arrow defs (ISSUE-012)"`

---

## Subsystem D — dedupe (ordered: D1 before D2)

D1 and D2 pull the dedupe key in opposite directions (narrower vs broader identity). Implement D1 first, then D2 as a separate second pass. `fingerprint.py` is NOT touched (Go-parity).

### Task D1 — ISSUE-016: preserve distinct findings at the same site

**Files:** Modify `helpers/sec_harness/dedupe.py` (grouping key at lines 55-58); Test `helpers/tests/test_dedupe.py`.

**Interfaces:**
- Consumes: `Finding.dataflow: list[str]` (frozen model field, read-only).
- Produces: two same-`(file,line,cls)` findings with differing `dataflow` both survive.

- [ ] **Step 1 (RED):** Add to `tests/test_dedupe.py`:

```python
def test_dedupe_preserves_distinct_findings_at_same_site(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    a = Finding(id="F-1", rule_id="r", cls="ssrf", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=18, message="m",
                dataflow=["req.body.url", "isPrivateIp", "fetch"])
    b = Finding(id="F-2", rule_id="r", cls="ssrf", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=18, message="m",
                dataflow=["req.query.target", "isPrivateIp", "axios.get"])
    write_findings(ws, [a, b])
    assert dedupe_findings(ws) == 0
    statuses = {f.id: f.status for f in read_findings(ws)}
    assert statuses["F-1"] is FindingStatus.RAW and statuses["F-2"] is FindingStatus.RAW
```

- [ ] **Step 2:** Run it — expect FAIL (currently merges to 1).
- [ ] **Step 3 (GREEN):** Change the same-class grouping key from `(f.file, f.line, f.cls)` to `(f.file, f.line, f.cls, tuple(f.dataflow) or f.message)`. Keep the highest-severity-wins merge for genuine collisions on the new key.
- [ ] **Step 4:** Run the full `tests/test_dedupe.py` — expect PASS (existing tests still hold; `test_dedupe_leaves_distinct_findings` unaffected).
- [ ] **Step 5:** `ruff` + `ty`. Commit: `git add skills/sec-harness/helpers/sec_harness/dedupe.py skills/sec-harness/helpers/tests/test_dedupe.py && git commit -m "fix(dedupe): preserve distinct findings at same site by dataflow (ISSUE-016)"`

### Task D2 — ISSUE-018: merge same-fact findings across classes

**Files:** Modify `helpers/sec_harness/dedupe.py` (add a second pass after the same-class pass); Test `helpers/tests/test_dedupe.py`.

**Interfaces:**
- Consumes: the D1-modified `dedupe_findings`.
- Produces: two findings with the same `(file, line, non-empty dataflow-signature)` but different `cls` merge to one, the other marked `DUPLICATE`.

- [ ] **Step 1 (RED):** Add to `tests/test_dedupe.py`:

```python
def test_dedupe_merges_same_fact_across_classes(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    a = Finding(id="F-1", rule_id="r", cls="ssrf", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=18, message="m",
                dataflow=["req.body.url", "fetch"])
    b = Finding(id="F-2", rule_id="r", cls="authz", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=18, message="m",
                dataflow=["req.body.url", "fetch"])
    write_findings(ws, [a, b])
    assert dedupe_findings(ws) == 1
    statuses = {f.id: f.status for f in read_findings(ws)}
    assert FindingStatus.DUPLICATE in statuses.values()
```

- [ ] **Step 2:** Run it — expect FAIL (currently returns 0; different `cls` never share a key).
- [ ] **Step 3 (GREEN):** After the existing same-class pass, add a cross-class pass: group remaining active findings by `(f.file, f.line, tuple(f.dataflow))` ONLY when `f.dataflow` is non-empty (never merge dataflow-less findings, to avoid false cross-class merges). Within a group, keep the highest-severity member; mark the rest `DUPLICATE` reusing the existing merge helper. Return the total merge count across both passes.
- [ ] **Step 4:** Run the full `tests/test_dedupe.py` — both new tests and all existing PASS. Confirm D1's test still returns 0 (its two findings have DIFFERENT dataflow, so the cross-class pass does not merge them).
- [ ] **Step 5:** `ruff` + `ty`. Commit: `git commit -m "fix(dedupe): merge same-fact findings across class framings (ISSUE-018)"`

---

## Subsystem E — phase gates

### Task E1 — ISSUE-008: markdown claim-extractor for free-text KB

**Files:** Modify `helpers/sec_harness/phase_gate.py` (add after `claims_from_context`, ~line 172); Test `helpers/tests/test_phase_gate.py`.

**Interfaces:**
- Produces: `claims_from_markdown(text: str) -> list[dict]` returning `{"id": "md-<i>", "text": <line>, "refs": ["<path>:<line>"]}` for genuine `path.ext:line` citations only — never prose file mentions.

- [ ] **Step 1 (RED):** Add to `tests/test_phase_gate.py`:

```python
def test_claims_from_markdown_extracts_only_file_line_citations():
    from sec_harness.phase_gate import claims_from_markdown
    md = ("The gateway validates tokens in server/api/x.py:12 before dispatch.\n"
          "Also see server/api/y.py:40 for the session check.\n"
          "See the README for background; ARCHITECTURE mentions this too.\n")
    claims = claims_from_markdown(md)
    assert len(claims) == 2
    assert {c["refs"][0] for c in claims} == {"server/api/x.py:12", "server/api/y.py:40"}
    assert all(c["id"].startswith("md-") for c in claims)
```

- [ ] **Step 2:** Run it — expect FAIL (no such function).
- [ ] **Step 3 (GREEN):** Implement `claims_from_markdown` using an extension-anchored regex requiring a mandatory `:line`:
  `r"\b([\w./-]+\.(?:py|js|ts|tsx|jsx|go|java|rb|php|c|cc|cpp|rs)):(\d+)\b"`.
  One claim per match, `id=f"md-{i}"`, `text` = the full line containing the match, `refs=[f"{path}:{line}"]`. No existence check here (that is `ref_resolves`' job downstream).
- [ ] **Step 4:** Run it — expect PASS.
- [ ] **Step 5:** `ruff` + `ty`. Commit: `git add skills/sec-harness/helpers/sec_harness/phase_gate.py skills/sec-harness/helpers/tests/test_phase_gate.py && git commit -m "feat(phase-gate): claims_from_markdown for free-text KB (ISSUE-008)"`

### Task E2 — ISSUE-006: recon gate challenges attack_surface

**⚠️ Pre-check (shared contract):** This task adds a field to `ScanProfile`. Before implementing, confirm `ScanProfile` is NOT in the Go golden set (goldens are `Finding`/`CampaignState` from `models.py` per root CLAUDE.md). Run `rg -n "ScanProfile|scan-profile|attack_surface" go/ 2>/dev/null` from the repo root. If Go mirrors it, STOP and coordinate; otherwise proceed (it is not the frozen contract).

**Files:** Modify `helpers/sec_harness/profile.py` (add `attack_surface_evidence: dict[str, list[str]]`), `helpers/sec_harness/phase_gate.py` (`claims_from_profile`), `agents/recon.md`; Test `helpers/tests/test_phase_gate.py`.

**Interfaces:**
- Consumes: `profile.attack_surface`, new `profile.attack_surface_evidence`.
- Produces: `claims_from_profile` emits one `{"id": "surf-<key>", ...}` claim per attack-surface entry, `refs` = its evidence `file:line` list (empty → routes `to-adversary` on judgment, not auto-reject).

- [ ] **Step 1 (RED):** Add to `tests/test_phase_gate.py`:

```python
def test_claims_from_profile_extracts_attack_surface_claims():
    from types import SimpleNamespace
    from sec_harness.phase_gate import claims_from_profile
    p = SimpleNamespace(entrypoints=[], subsystems=[], attack_surface=["sqli"],
                        agents_to_spawn=["sqli"],
                        attack_surface_evidence={"sqli": ["src/db.py:10"]})
    claims = claims_from_profile(p)
    surf = next(c for c in claims if c["id"] == "surf-sqli")
    assert surf["refs"] == ["src/db.py:10"] and "sqli" in surf["text"]
```

- [ ] **Step 2:** Run it — expect FAIL.
- [ ] **Step 3 (GREEN):** Add `attack_surface_evidence: dict[str, list[str]] = field(default_factory=dict)` to `ScanProfile` (with `to_dict`/`from_dict` round-trip if the class defines them — verify it is not the frozen module). In `claims_from_profile`, loop over `attack_surface` emitting `{"id": f"surf-{k}", "text": f"attack_surface includes {k}", "refs": evidence.get(k, [])}` via `getattr(profile, "attack_surface_evidence", {})`.
- [ ] **Step 4:** In `agents/recon.md`, instruct recon to populate `attack_surface_evidence` mapping each selected class to the `file:line` indicator that justified it.
- [ ] **Step 5:** Run tests — expect PASS. `ruff` + `ty`.
- [ ] **Step 6:** Commit: `git add skills/sec-harness/helpers/sec_harness/profile.py skills/sec-harness/helpers/sec_harness/phase_gate.py skills/sec-harness/agents/recon.md skills/sec-harness/helpers/tests/test_phase_gate.py && git commit -m "feat(recon-gate): challenge attack_surface with evidence claims (ISSUE-006)"`

### Task E3 — ISSUE-023: produce kb/gates/redteam.json

**Files:** Modify `helpers/sec_harness/redteam.py` (add `build_redteam_gate_record`, wire into the plan writer); Test `helpers/tests/test_redteam.py`.

**Interfaces:**
- Consumes: needs-runtime `Finding`s, `phase_gate.build_gate_record`/`write_gate_record`.
- Produces: `build_redteam_gate_record(findings, verdicts=None) -> dict` in the same record shape `write_gate_record` expects; `kb/gates/redteam.json` is actually written.

- [ ] **Step 1 (RED):** Add to `tests/test_redteam.py` a test that builds a redteam gate record from one needs-runtime finding, asserts `rec["phase"] == "redteam"`, the finding's `refs == ["<file>:<line>"]`, a `WEAKENED` verdict leaves it in `survivors`, and `write_gate_record(ws, "redteam", rec).name == "redteam.json"`. (Read the existing `tests/test_redteam.py` helpers first to reuse a finding factory.)
- [ ] **Step 2:** Run it — expect FAIL (no `build_redteam_gate_record`).
- [ ] **Step 3 (GREEN):** Implement `build_redteam_gate_record`: map each finding to a claim-shaped `GateDecision(status="to-adversary", claim_id=f.id, text=f.title or f.message, refs=[f"{f.file}:{f.line}"])`, then delegate to `phase_gate.build_gate_record("redteam", decisions, verdicts)`. Do not re-run `ref_resolves` (findings are already tool-receipt gated upstream). Wire a call into `redteam.write_plan` (or `main`) so the record is written whenever the plan is generated.
- [ ] **Step 4:** Run tests — expect PASS. `ruff` + `ty`.
- [ ] **Step 5:** Confirm `agents/redteam-adversary.md` verdict vocab (`CONFIRMED`/`WEAKENED`/`INVALIDATED`) already matches `build_gate_record`; no prompt change needed (documented — the ISSUE-023 "vocab mismatch" was a mischaracterization; the real defect was the missing writer).
- [ ] **Step 6:** Commit: `git add skills/sec-harness/helpers/sec_harness/redteam.py skills/sec-harness/helpers/tests/test_redteam.py && git commit -m "feat(redteam): emit kb/gates/redteam.json gate record (ISSUE-023)"`

---

## Subsystem F — verify / report / orchestration / crypto

### Task F1 — ISSUE-021: verify re-runs the finding's own backend

**Files:** Modify `helpers/sec_harness/verify.py` (imports at 49-50; `verify_patch` 130-168; `_file_has_hit` 104-127; `verify_findings` 171-201); Test `helpers/tests/test_verify.py`.

**Interfaces:**
- Consumes: `Finding.evidence_sources` prefixes (`semgrep:` / `codeql:` / `sca:`), `sast.run_semgrep`, `codeql.run_codeql`, `sca.run_sca`.
- Produces: a codeql-origin finding is re-checked with codeql, not semgrep; unknown/absent backend falls back to `static-only` (never a false clean).

- [ ] **Step 1 (RED):** Add to `tests/test_verify.py`:

```python
def test_codeql_finding_routes_to_codeql_rerun(monkeypatch):
    import sec_harness.verify as V
    calls = []
    monkeypatch.setattr(V, "run_semgrep",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no semgrep")))
    monkeypatch.setattr(V, "run_codeql", lambda target, **k: calls.append(target) or [])
    V.verify_patch("/tgt", "diff", "cfg", "app.py", "sqli",
                   evidence_sources=["codeql:py/sql-injection"])
    assert calls
```

- [ ] **Step 2:** Run it — expect FAIL (no `run_codeql` import/branch).
- [ ] **Step 3 (GREEN):** Add a backend picker: inspect `evidence_sources` prefixes, dispatch to the matching runner (`run_semgrep`/`run_codeql`/`run_sca`), generalize `_semgrep_rules` → `_source_rules(prefix, evidence_sources)`. Thread `run_codeql`'s `language`/`db_dir` as optional kwargs on `verify_patch`/`verify_findings`; when unavailable, keep the finding at `static-only` (explicit, not silent-clean). Default to semgrep when no codeql/sca prefix is present (existing tests unaffected).
- [ ] **Step 4:** Run the full `tests/test_verify.py` — expect PASS. `ruff` + `ty`.
- [ ] **Step 5:** Commit: `git add skills/sec-harness/helpers/sec_harness/verify.py skills/sec-harness/helpers/tests/test_verify.py && git commit -m "fix(verify): re-run the finding's own backend, not just semgrep (ISSUE-021)"`

### Task F2 — ISSUE-027: calibrate promotes runtime-dependent findings

**Files:** Modify `helpers/sec_harness/calibrate.py` (`calibrate_findings`, ~line 130); Test `helpers/tests/test_calibrate.py`.

**Interfaces:**
- Consumes: `campaign.promote_runtime_dependent`.
- Produces: after `calibrate_findings`, a `raw`+`runtime_dependent` finding is `needs-deployment-testing`.

- [ ] **Step 1 (RED):** Add to `tests/test_calibrate.py`:

```python
def test_calibrate_promotes_runtime_dependent_before_scoring(tmp_path):
    from sec_harness.calibrate import calibrate_findings
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.workspace import Workspace, read_findings, write_findings
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    write_findings(ws, [Finding(id="A", rule_id="r", cls="business-logic",
                                status=FindingStatus.RAW, severity=Severity.LOW,
                                file="a.py", line=1, message="m", runtime_dependent=True)])
    calibrate_findings(ws)
    by = {f.id: f.status for f in read_findings(ws)}
    assert by["A"] is FindingStatus.NEEDS_DEPLOYMENT_TESTING
```

- [ ] **Step 2:** Run it — expect FAIL (stays RAW).
- [ ] **Step 3 (GREEN):** At the top of `calibrate_findings`, call `from sec_harness.campaign import promote_runtime_dependent; promote_runtime_dependent(ws)` before reading/scoring (re-read findings after). No schema change.
- [ ] **Step 4:** Run tests — expect PASS. `ruff` + `ty`.
- [ ] **Step 5:** Update `SKILL.md` phase table so promotion is documented as happening inside calibrate (remove any implication it is a separate manual step).
- [ ] **Step 6:** Commit: `git add skills/sec-harness/helpers/sec_harness/calibrate.py skills/sec-harness/helpers/tests/test_calibrate.py skills/sec-harness/SKILL.md && git commit -m "fix(calibrate): auto-promote runtime-dependent findings (ISSUE-027)"`

### Task F3 — ISSUE-019 + ISSUE-013: report-layer disposition split (Go-safe)

**Files:** Modify `helpers/sec_harness/report.py` (`to_markdown`, needs-deployment block 137-148) and `helpers/sec_harness/redteam.py` (needs-runtime rendering); Test `helpers/tests/test_report.py`.

**Interfaces:**
- Produces: needs-deployment findings render under two sub-headings — "Code-settled, runtime-impact-pending" (non-empty `dataflow` AND `preconditions`) before "Verification-incomplete" (the rest). No status/enum/model change.

- [ ] **Step 1 (RED):** Add to `tests/test_report.py`:

```python
def test_needs_deployment_split_by_dataflow_presence(tmp_path):
    from sec_harness.report import to_markdown
    from sec_harness.models import Finding, FindingStatus, Severity
    settled = Finding(id="A", rule_id="r", cls="sqli",
                      status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.HIGH,
                      file="a.py", line=1, message="m", dataflow=["src", "sink"],
                      preconditions=["auth"])
    incomplete = Finding(id="B", rule_id="r", cls="sqli",
                         status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.HIGH,
                         file="b.py", line=1, message="m", verification="verify-error")
    md = to_markdown([], needs_deployment=[settled, incomplete])
    assert "code-settled, runtime-impact-pending" in md.lower()
    assert md.lower().index("code-settled") < md.index("A") < md.index("B")
```

- [ ] **Step 2:** Run it — expect FAIL.
- [ ] **Step 3 (GREEN):** In `to_markdown`, split `needs_deployment` into `settled = [f for f in needs_deployment if f.dataflow and f.preconditions]` and `incomplete = [the rest]`; render two subsections under the existing heading: "### Code-settled, runtime-impact-pending" then "### Verification-incomplete". Mirror the grouping in `redteam.py`'s needs-runtime section.
- [ ] **Step 4:** Run the full `tests/test_report.py` — expect PASS (existing heading test still holds).
- [ ] **Step 5:** `ruff` + `ty`. Commit: `git add skills/sec-harness/helpers/sec_harness/report.py skills/sec-harness/helpers/sec_harness/redteam.py skills/sec-harness/helpers/tests/test_report.py && git commit -m "fix(report): split needs-deployment by code-settled vs incomplete (ISSUE-019/013)"`

### Task F4 — ISSUE-026: crypto_policy flags CBC-without-AEAD and bare-hash KDF

**Files:** Modify `helpers/sec_harness/crypto_policy.py` (`check`, line 24); Create `helpers/tests/test_crypto_policy.py`.

**Interfaces:**
- Produces: `check("aes-256-cbc")["ok"] is False`; `check("sha256", params={"kdf_context": True})["ok"] is False`. Existing approved algos (e.g. `aes-256-gcm`) still `ok:true`.

- [ ] **Step 1 (RED):** Create `helpers/tests/test_crypto_policy.py`:

```python
from sec_harness.crypto_policy import check

def test_cbc_without_aead_is_denied():
    assert check("aes-256-cbc")["ok"] is False

def test_gcm_still_ok():
    assert check("aes-256-gcm")["ok"] is True

def test_bare_hash_as_kdf_is_denied():
    assert check("sha256", params={"kdf_context": True})["ok"] is False
```

- [ ] **Step 2:** Run it — expect the CBC and KDF tests FAIL, the GCM test PASS.
- [ ] **Step 3 (GREEN):** In `check`, after the deny-set loop: (a) if `a` contains a non-AEAD mode (`cbc`/`cfb`/`ofb`, or `ecb` already denied) and lacks an AEAD/MAC indicator (`gcm`/`ccm`/`poly1305`/`hmac`), append `"non-AEAD block cipher mode without MAC: {algo}"`; (b) if `params.get("kdf_context")` is truthy and `a` is a bare fast hash (`sha256`/`sha512`/`md5`/`sha1` with no `pbkdf2`/`bcrypt`/`scrypt`/`argon2` substring), append `"bare fast hash used as KDF: {algo}"`. `params` is already an untyped dict — the new key is Go-safe.
- [ ] **Step 4:** Run tests — expect PASS. `ruff` + `ty`.
- [ ] **Step 5:** Commit: `git add skills/sec-harness/helpers/sec_harness/crypto_policy.py skills/sec-harness/helpers/tests/test_crypto_policy.py && git commit -m "fix(crypto-policy): flag CBC-no-AEAD and bare-hash KDF (ISSUE-026)"`

### Task F5 — ISSUE-022: redteam surfaces prime-manual-test None-risk findings (low priority)

**Files:** Modify `helpers/sec_harness/redteam.py` (`_above_bar`, 40-50); Test `helpers/tests/test_redteam.py`.

**Interfaces:**
- Produces: a finding carrying a `{"event": "redteam:prime-manual-test"}` history entry clears `_above_bar` even at low severity + `risk_score=None`.

- [ ] **Step 1 (RED):** Add a test asserting `_above_bar(f, min_risk=7)` is `True` for a low-severity, `risk_score=None` finding whose `history` contains `{"event": "redteam:prime-manual-test"}`.
- [ ] **Step 2:** Run it — expect FAIL (drops to below-bar today).
- [ ] **Step 3 (GREEN):** Add a third OR branch to `_above_bar`: `any(h.get("event") == "redteam:prime-manual-test" for h in f.history)`. `history` is an untyped list of dicts — Go-safe.
- [ ] **Step 4:** Run tests — expect PASS. `ruff` + `ty`.
- [ ] **Step 5:** Commit: `git commit -m "fix(redteam): surface prime-manual-test None-risk findings (ISSUE-022)"`

### Task F6 — ISSUE-017: serialize FP-ladder writes to one finding file

**Files:** Modify `SKILL.md` (Phase 8 orchestration); optionally `agents/judge.md`/`agents/validate.md` note.

**Interfaces:** No code change to `write_findings` (already atomic per file). The fix is orchestration: judge and validate must not concurrently read-modify-write the same `findings/<id>.json`.

- [ ] **Step 1:** In `SKILL.md` Phase 8, change any wording that runs judge "with"/concurrently to validate so judge completes and persists BEFORE validate begins (sequential per finding). State explicitly: never dispatch two agents that write the same finding file in the same wave — the last writer wins and silently drops the other's field.
- [ ] **Step 2:** Add a one-line note to `agents/judge.md` and `agents/validate.md` Output sections: "You may be one of several writers of this file across phases; only ever modify your own fields, and assume your write is sequenced after the prior phase's — do not run concurrently with another writer of the same id."
- [ ] **Step 3:** Commit: `git add skills/sec-harness/SKILL.md skills/sec-harness/agents/judge.md skills/sec-harness/agents/validate.md && git commit -m "fix(orchestration): serialize judge/validate writes per finding (ISSUE-017)"`

---

## Deferred / not in this batch

- **ISSUE-011 already-fixed portion** (resource/DoS CWE routing) landed in `79a745b`; B1 completes the robust `unknown`→`security-other` reroute.
- **Frozen-contract paths not taken:** 013/019 are solved at the report layer (F3), not by a new disposition enum. If a first-class `code-settled` status is later wanted, it requires a coordinated `models.py`/`evidence.py` change + Go golden regen — out of scope here per the Go-safe decision.
- **ISSUE-012 multi-hop caller resolution** is out of scope (architectural limit of a ripgrep-backed index).

---

## Self-Review

- **Spec coverage:** every batched issue 003–027 maps to a task (003→A1, 004→A2, 005→A3, 006→E2, 007→A4, 008→E1, 010→A5, 011→B1, 012→C1, 013→F3, 014→A6, 016→D1, 017→F6, 018→D2, 019→F3, 020→A7, 021→F1, 022→F5, 023→E3, 024→A8, 025→A9, 026→F4, 027→F2). 009/015 already fixed.
- **Ordering:** D1 before D2 (dedupe tension); E2 has a shared-contract pre-check gate; B1/C1/F1/F2/F4 are independent recall-critical fixes.
- **Type consistency:** all test code uses `Finding(...)` kwargs present on the frozen model (`dataflow`, `preconditions`, `runtime_dependent`, `verification`, `history`, `evidence_sources`) — none add fields to frozen modules. Only E2 adds a field, to non-frozen `profile.py`, behind a pre-check.
