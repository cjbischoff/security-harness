# Report Readability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the single-repo human report lead with the real story — honest counts (confirmed and needs-runtime tallied separately), a risk-ordered triage table with real leads above dep CVEs, a purpose-built view for needs-runtime and dependency findings, and a redteam-plan that renders markdown instead of raw Python `repr`.

**Architecture:** Presentation-layer only, in `helpers/sec_harness/report.py` and `helpers/sec_harness/redteam.py`, plus doc extension of `references/finding-template.md`. Every view is populated from existing `Finding` fields — no analysis, scoring, status, `models.py`, `evidence.py`, or `go/` change. Deterministic, golden-string tested.

**Tech Stack:** Python 3 stdlib-only; `uv run pytest`; ruff (line-length 100) + ty. Run all commands from `skills/sec-harness/helpers`.

## Global Constraints

- **stdlib-only**; no new dependencies.
- **No `models.py` / `evidence.py` / `go/` change**; no new `Finding` field; no findings added/removed/re-scored. This is a view change — confirm zero `go/` files change on the branch.
- **Epistemic honesty (LOAD-BEARING):** needs-deployment-testing findings are ALWAYS labeled needs-runtime and counted separately from confirmed — NEVER merged into the confirmed severity counts, never shown as confirmed.
- **Determinism:** every emitter sorts its rows; identical input → byte-identical output (golden-tested).
- **No literal secrets** in emitted output; redteam payloads already use `$SHELL_VAR` (unchanged here).
- Conventional commits; all paths under `skills/sec-harness/`.

## File Structure

- `helpers/sec_harness/redteam.py` — `_directive_block` (markdown serialization of preconditions/expected_signal/telemetry) + two small helpers.
- `helpers/sec_harness/report.py` — `render_finding` (dep-view branch + renumbered condensed tier), new `render_ndt`, `_triage_row`, and `to_markdown` restructure (bottom-line + triage table + reordered sections).
- `references/finding-template.md` — add triage-line, NDT-view, dep-view; renumber condensed tier note.
- Tests: `tests/test_redteam.py` (extend or create), `tests/test_report.py` (extend), `tests/test_docs_invariants.py` (template contract).

---

### Task 1: redteam-plan serializer — markdown, not repr

**Files:**
- Modify: `helpers/sec_harness/redteam.py` (`_directive_block`, lines ~118-128)
- Test: `helpers/sec_harness/tests/test_redteam.py`

**Interfaces:**
- Consumes: `Finding.runtime_test` dict with `preconditions` (list[str]), `expected_signal` (dict `{secure,insecure}`), `telemetry` (list[str]).
- Produces: two module-level helpers `_bullets(items) -> str`, `_signal(d) -> str`.

- [ ] **Step 1: Write the failing test**

```python
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.redteam import _directive_block


def _ndt(**rt):
    return Finding(rule_id="investigation:authz", cls="authz",
                   status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.MEDIUM,
                   file="src/rbac/spec.js", line=133, message="cross-CE write",
                   risk_score=5, runtime_test=rt)


def test_directive_renders_markdown_not_repr():
    f = _ndt(objective="verify CE-ID isolation",
             preconditions=["Two distinct TaaS CEs (CE-A, CE-B)", "low-priv user in CE-A"],
             expected_signal={"secure": "403 forbidden", "insecure": "201 + record"},
             telemetry=["service access logs", "audit log"])
    out = _directive_block(f)
    assert "['" not in out and "{'" not in out          # no python repr
    assert "\n  - Two distinct TaaS CEs (CE-A, CE-B)" in out   # precondition bullet
    assert "**secure:**" in out and "403 forbidden" in out     # labeled signal
    assert "**insecure:**" in out and "201 + record" in out
    assert "\n  - service access logs" in out                  # telemetry bullet
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_redteam.py::test_directive_renders_markdown_not_repr -q`
Expected: FAIL (`['` present — current code interpolates the raw list).

- [ ] **Step 3: Write minimal implementation**

Add two helpers above `_directive_block`:

```python
def _bullets(items: object) -> str:
    """Render a list of strings as indented markdown bullets (deterministic order preserved).

    Args:
        items: A list of strings, or any other value.

    Returns:
        Newline-joined ``  - <item>`` bullets, or ``_not specified_`` when not a non-empty list.
    """
    if isinstance(items, list) and items:
        return "\n".join(f"  - {str(x)}" for x in items)
    return "_not specified_"


def _signal(d: object) -> str:
    """Render an expected-signal dict as labeled secure/insecure sub-fields.

    Args:
        d: A dict with ``secure``/``insecure`` keys, or any other value.

    Returns:
        Two indented ``**secure:** …`` / ``**insecure:** …`` lines, or ``_not specified_``.
    """
    if isinstance(d, dict) and d:
        return (f"\n  - **secure:** {d.get('secure', '_unspecified_')}"
                f"\n  - **insecure:** {d.get('insecure', '_unspecified_')}")
    return "_not specified_"
```

Then in `_directive_block`, replace the three raw interpolations:

```python
        f"- **Preconditions / access:**\n{_bullets(rt.get('preconditions'))}",
        "- **Payload(s)** (shell vars only — export before use):",
        payload_md,
        f"- **Expected signal:**{_signal(rt.get('expected_signal'))}",
        f"- **Telemetry to watch:**\n{_bullets(rt.get('telemetry'))}",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_redteam.py -q && uv run ruff check sec_harness/redteam.py tests/test_redteam.py && uv run ty check sec_harness/redteam.py`
Expected: PASS, clean. (If pre-existing redteam tests assert the old raw format, update them to the markdown format — that is the intended change, not a regression.)

- [ ] **Step 5: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/redteam.py skills/sec-harness/helpers/tests/test_redteam.py
git commit -m "fix(redteam): render preconditions/expected_signal/telemetry as markdown, not repr"
```

---

### Task 2: dep-view + renumber condensed tier in `render_finding`

**Files:**
- Modify: `helpers/sec_harness/report.py` (`render_finding`, lines ~25-103)
- Test: `helpers/sec_harness/tests/test_report.py`

**Interfaces:**
- Consumes: `Finding.cls`, `.evidence` (`package@version`), `.rule_id`/`.evidence_sources` (advisory), `.reachability` (`{reachable, blocker}`).
- Produces: a dep-view branch inside `render_finding`; condensed non-dep tier renumbered `1,2,3,4`.

Behavior: when `f.cls == "deps"`, render a purpose-built block (Summary with `package@version` + advisory; Reachability line from `f.reachability`; Fix = bump) and RETURN — do not emit the `(no dataflow)/(no vector)/(no patch)` slots. For non-dep condensed (medium/low) findings, emit sections numbered `1,2,3,4` (Summary, Mechanism, Severity, Fix) — no gap. Full tier (critical/high) unchanged (still 9 sections).

- [ ] **Step 1: Write the failing test**

```python
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.report import render_finding


def _dep():
    return Finding(rule_id="osv:GHSA-x", cls="deps", status=FindingStatus.CONFIRMED,
                   severity=Severity.LOW, file="package-lock.json", line=1,
                   message="decompress@4.2.1: GHSA-x — archive path traversal",
                   evidence="decompress@4.2.1", evidence_sources=["sca:osv:GHSA-x"],
                   reachability={"reachable": False, "blocker": "dev-build-only"})


def _code_low():
    return Finding(rule_id="r", cls="authz", status=FindingStatus.CONFIRMED, severity=Severity.LOW,
                   file="a.js", line=9, message="thing", dataflow=["src -> sink"])


def test_dep_view_has_no_hollow_slots():
    out = render_finding(_dep())
    assert "(no dataflow recorded)" not in out
    assert "(no vector)" not in out
    assert "(no patch generated" not in out
    assert "decompress@4.2.1" in out
    assert "reachable" in out.lower() and "dev-build-only" in out    # reachability surfaced
    assert "GHSA-x" in out


def test_condensed_tier_renumbers_without_gaps():
    out = render_finding(_code_low())
    assert "**1. Summary" in out and "**2. Mechanism" in out
    assert "**3. Severity" in out and "**4. Fix" in out              # renumbered, no gap
    assert "**5. " not in out and "**7. " not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_report.py -q -k "dep_view or condensed_tier"`
Expected: FAIL (dep hits hollow slots; condensed renders `5`/`7`).

- [ ] **Step 3: Write minimal implementation**

At the top of `render_finding` (after the header line, before §1), add the dep-view branch:

```python
    if f.cls == "deps":
        reach = f.reachability or {}
        rstate = "reachable" if reach.get("reachable") else "not reachable"
        blocker = reach.get("blocker") or "—"
        adv = f.rule_id if f.rule_id.startswith("osv:") else (
            next((s for s in f.evidence_sources if "osv:" in s), f.rule_id))
        pkg = (f.evidence or "").strip() or "(package unknown)"
        out = [f"### {f.id} — deps — {f.severity.value.title()}", "",
               f"**Package.** `{pkg}` — advisory `{adv}`.  ",
               f"Location: `{f.file}:{f.line}`.", "",
               f"**Reachability.** {rstate} in this repo (blocker: {blocker}). "
               f"{f.message.split('|', 1)[0].strip()}", "",
               f"**Fix.** Bump `{pkg.split('@')[0]}` to a release that resolves `{adv}`.", ""]
        return "\n".join(out)
```

Then renumber the condensed path. The condensed (non-full) tier currently emits `**5. Severity`, `**Confirmation:**`, `**7. Fix.**`. Change the non-`full` numbering so the condensed sequence reads `1 Summary, 2 Mechanism, 3 Severity, 4 Fix`. Concretely, gate the section numbers on `full`:
- Severity header: `**3. Severity Rationale.**` when `not full`, `**5. Severity Rationale.**` when `full`.
- Fix header: `**4. Fix.**` when `not full`, `**7. Fix.**` when `full`.

Use a small local:

```python
    sev_no, fix_no = ("5", "7") if full else ("3", "4")
```

and interpolate `sev_no`/`fix_no` into the Severity and Fix headers. (The full tier keeps 1,2,3,4,5,6,7,8; the condensed tier now reads 1,2,3,4.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_report.py -q && uv run ruff check sec_harness/report.py tests/test_report.py && uv run ty check sec_harness/report.py`
Expected: PASS, clean. (Update any pre-existing golden test that asserted the old `5/7` condensed numbering or the dep hollow slots — that is the intended change.)

- [ ] **Step 5: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/report.py skills/sec-harness/helpers/tests/test_report.py
git commit -m "feat(report): dep-view for dependency findings; renumber condensed tier (no gaps)"
```

---

### Task 3: `render_ndt` — a real view for needs-runtime findings

**Files:**
- Modify: `helpers/sec_harness/report.py` (new `render_ndt` function)
- Test: `helpers/sec_harness/tests/test_report.py`

**Interfaces:**
- Consumes: `Finding.message`, `.dataflow`, `.preconditions`, `.runtime_test` (`objective`, `expected_signal.{secure,insecure}`).
- Produces: `render_ndt(f: Finding) -> str`.

Renders a foregrounded, always-labeled-needs-runtime view: heading, one-line what/why (`message`), the source-side `dataflow` chain, `preconditions`, and the concrete test (`runtime_test.objective` + secure/insecure signal), with a pointer to `redteam-plan.md`. Never says "confirmed."

- [ ] **Step 1: Write the failing test**

```python
from sec_harness.report import render_ndt


def _ndt():
    return Finding(rule_id="investigation:authz", cls="authz",
                   status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.MEDIUM,
                   file="src/rbac/spec.js", line=133, risk_score=5,
                   message="sole unrestrictedInTaas write; cross-CE injection if Go handler unscoped",
                   dataflow=["privilege(unrestrictedInTaas) @ spec.js:133", "-> Go handler UNVERIFIED"],
                   preconditions=["Go handler does not enforce per-CE isolation"],
                   runtime_test={"objective": "verify CE-ID isolation on operatorFeedbackWrite",
                                 "expected_signal": {"secure": "403", "insecure": "201 + CE-B record"}})


def test_render_ndt_labels_needs_runtime_and_shows_test():
    out = render_ndt(_ndt())
    assert "needs runtime" in out.lower()                 # always labeled
    assert "confirmed" not in out.lower()                 # never laundered
    assert "spec.js:133" in out
    assert "verify CE-ID isolation" in out                # the test objective
    assert "403" in out and "201 + CE-B record" in out    # secure/insecure signal
    assert "redteam-plan.md" in out                       # pointer to the runnable test
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_report.py::test_render_ndt_labels_needs_runtime_and_shows_test -q`
Expected: FAIL (`render_ndt` not defined).

- [ ] **Step 3: Write minimal implementation**

```python
def render_ndt(f: Finding) -> str:
    """Render a needs-deployment-testing finding as a foregrounded, needs-runtime-labeled view.

    Populated from the fields an NDT finding actually carries — ``message`` (what/why),
    ``dataflow`` (source-side chain), ``preconditions``, and ``runtime_test`` (objective +
    secure/insecure signal). Always labeled needs-runtime and never described as confirmed; the
    runnable payloads/telemetry live in ``redteam-plan.md``.

    Args:
        f: A needs-deployment-testing finding.

    Returns:
        A Markdown section string for the finding.
    """
    rt = f.runtime_test or {}
    sig = rt.get("expected_signal") or {}
    flow = "\n".join(f"  - `{hop}`" for hop in (f.dataflow or [])) or "  - (no source chain recorded)"
    pre = "\n".join(f"  - {p}" for p in (f.preconditions or [])) or "  - (none recorded)"
    out = [f"### {f.id} — {f.cls} — {f.severity.value.title()} · needs runtime proof", "",
           f"**What.** {f.message}  \nLocation: `{f.file}:{f.line}`.", "",
           "**Source-side chain.**", flow, "",
           "**Preconditions (out-of-repo barrier).**", pre, ""]
    if rt.get("objective"):
        out += [f"**Runtime test.** {rt['objective']}"]
        if sig:
            out += [f"  - **secure:** {sig.get('secure', '_unspecified_')}",
                    f"  - **insecure:** {sig.get('insecure', '_unspecified_')}"]
        out += ["_Runnable payloads + telemetry: see `redteam-plan.md`._", ""]
    return "\n".join(out)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_report.py -q && uv run ruff check sec_harness/report.py tests/test_report.py && uv run ty check sec_harness/report.py`
Expected: PASS, clean.

- [ ] **Step 5: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/report.py skills/sec-harness/helpers/tests/test_report.py
git commit -m "feat(report): render_ndt — foregrounded needs-runtime view (never laundered to confirmed)"
```

---

### Task 4: `to_markdown` restructure — bottom-line + triage table + reordered sections

**Files:**
- Modify: `helpers/sec_harness/report.py` (`to_markdown`, lines ~106-189; add `_triage_row`)
- Test: `helpers/sec_harness/tests/test_report.py`

**Interfaces:**
- Consumes: confirmed `findings` + `needs_deployment` (both already passed to `to_markdown`), `render_ndt` (Task 3), `render_finding` dep-view (Task 2).
- Produces: `_triage_row(f, status_label, action) -> str`; restructured `to_markdown`.

New structure (replacing the current Summary→Findings→Detailed→NDT-table order):
1. **Bottom line** — one sentence + a two-line count block: `Confirmed: <crit>/<high>/<med>/<low>` and `Needs runtime proof: <N>`. The confirmed counts NEVER include NDT findings; the needs-runtime line NEVER shows 0 when `needs_deployment` is non-empty.
2. **Triage** table — every finding (confirmed + NDT), risk-ordered desc (NDT risk_score included), each a `_triage_row`: `ID | what (first clause of message, ≤80 chars) | file:line | status (confirmed | needs-runtime) | next action`. Needs-runtime + higher risk sort above low deps.
3. **Needs runtime proof — the real leads** — `render_ndt` per NDT finding (risk desc), above confirmed.
4. **Confirmed (source-provable)** — `render_finding` per confirmed finding (deps get dep-view).
5. Coverage / redteam link / coverage-ledger / token-spend sections unchanged.

- [ ] **Step 1: Write the failing test**

```python
from sec_harness.report import to_markdown


def _confirmed_dep():
    return Finding(rule_id="osv:GHSA-x", cls="deps", status=FindingStatus.CONFIRMED,
                   severity=Severity.LOW, file="package-lock.json", line=1, risk_score=3,
                   message="decompress@4.2.1: GHSA-x — path traversal", evidence="decompress@4.2.1",
                   evidence_sources=["sca:osv:GHSA-x"], reachability={"reachable": False, "blocker": "dev"})


def _ndt_med():
    return Finding(rule_id="investigation:authz", cls="authz",
                   status=FindingStatus.NEEDS_DEPLOYMENT_TESTING, severity=Severity.MEDIUM,
                   file="src/rbac/spec.js", line=133, risk_score=5, message="cross-CE write lead",
                   dataflow=["a -> b"], preconditions=["handler unscoped"],
                   runtime_test={"objective": "verify isolation",
                                 "expected_signal": {"secure": "403", "insecure": "201"}})


def test_to_markdown_bottom_line_counts_ndt_separately():
    out = to_markdown([_confirmed_dep()], needs_deployment=[_ndt_med()])
    assert "Needs runtime proof: 1" in out                 # NDT counted, not hidden
    # confirmed count block must not fold the medium NDT into medium
    conf_line = next(l for l in out.splitlines() if l.startswith("Confirmed:"))
    assert "med" not in conf_line.lower() or "0" in conf_line  # NDT medium not in confirmed medium


def test_triage_puts_ndt_lead_above_low_dep():
    out = to_markdown([_confirmed_dep()], needs_deployment=[_ndt_med()])
    triage = out.split("## Triage")[1].split("##")[0]
    assert triage.index("AUTHZ") < triage.index("GHSA") or triage.index("needs-runtime") < triage.index("confirmed")
    assert "## Needs runtime proof" in out
    assert out.index("## Needs runtime proof") < out.index("## Confirmed")   # leads above confirmed
```

(Use whatever finding ids the fixtures produce; the load-bearing assertions are the count separation and the leads-above-confirmed ordering. Adjust the id substrings to match your fixtures.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_report.py -q -k "bottom_line or triage"`
Expected: FAIL (current output has `## Summary`, no `Needs runtime proof:` count line, NDT below confirmed in a bare table).

- [ ] **Step 3: Write minimal implementation**

Add `_triage_row` and rewrite the head of `to_markdown` (Summary + Findings table + Detailed + NDT-table blocks → the new structure). Keep coverage/redteam/ledger/token-spend tails exactly as they are. Sketch:

```python
def _triage_row(f: Finding, status_label: str, action: str) -> str:
    """Render one triage table row: id, one-clause what, location, status, next action.

    Args:
        f: The finding.
        status_label: ``confirmed`` or ``needs-runtime``.
        action: The next action phrase.

    Returns:
        A single Markdown table row.
    """
    what = (f.message or "").split("|", 1)[0].split(".")[0].strip()[:80]
    risk = f.risk_score if f.risk_score is not None else "-"
    return f"| {f.id} | {risk} | {what} | {f.file}:{f.line} | {status_label} | {action} |"
```

In `to_markdown`, build:
- `conf = sorted(findings, key=(-risk, id))`, `ndt = sorted(needs_deployment or [], key=(-risk, id))`.
- `conf_counts = Counter(f.severity.value for f in findings)` (confirmed only).
- Bottom line block:
  ```
  # sec-harness Report
  **Bottom line.** <one honest sentence built from the counts>
  Confirmed: {crit}/{high}/{med}/{low}
  Needs runtime proof: {len(ndt)}
  ```
  Never merge ndt into conf_counts.
- `## Triage` table: header `| ID | Risk | What | Location | Status | Next action |`; rows = all findings risk-ordered (merge conf+ndt, sort by -risk then id). Action: deps → "bump", other confirmed → "apply fix (§ below)", ndt → "run redteam-plan test".
- `## Needs runtime proof — the real leads` (only if `ndt`): `render_ndt(f)` per ndt, `---` separated.
- `## Confirmed (source-provable)` (only if `conf`): `render_finding(f, patch_status=...)` per conf, `---` separated.
- Then the existing coverage / has_redteam_plan / coverage_ledger / token_spend tail unchanged.

Drop the old `## Summary` per-severity list, the old `## Findings` table, the old `## Detailed findings`, and the old `## Needs deployment testing` bare-table block (its content is now the triage table + render_ndt).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_report.py -q && uv run ruff check sec_harness/report.py tests/test_report.py && uv run ty check sec_harness/report.py`
Expected: PASS, clean. Update any pre-existing `to_markdown` golden test to the new structure (intended change). Confirm the epistemic-honesty assertion (NDT never in confirmed counts) holds.

- [ ] **Step 5: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/report.py skills/sec-harness/helpers/tests/test_report.py
git commit -m "feat(report): bottom-line + risk-ordered triage table; leads above confirmed; NDT counted separately"
```

---

### Task 5: extend `finding-template.md` contract + doc-invariant test

**Files:**
- Modify: `references/finding-template.md`
- Test: `helpers/sec_harness/tests/test_docs_invariants.py` (append)

**Interfaces:**
- Consumes: nothing at runtime (doc contract). The test pins the load-bearing sections so the template stays the source of the views.

Add to the template: a **Triage line** subsection (the one-line-per-finding view), an **NDT-view** subsection (the needs-runtime condensed view + its field bindings), a **Dep-view** subsection (package/advisory/reachability/fix bindings), and change the Depth-tiers note so the condensed tier is documented as renumbered `1–4` (no gaps).

- [ ] **Step 1: Write the failing test**

```python
def test_finding_template_documents_triage_ndt_dep_views():
    p = Path(__file__).resolve().parents[2] / "references" / "finding-template.md"
    txt = p.read_text().lower()
    assert "triage line" in txt                       # skim layer documented
    assert "ndt-view" in txt or "needs-runtime view" in txt
    assert "dep-view" in txt or "dependency view" in txt
    assert "reachability" in txt                       # dep-view binding
    assert "renumber" in txt                           # condensed tier no-gap note
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_docs_invariants.py::test_finding_template_documents_triage_ndt_dep_views -q`
Expected: FAIL (sections absent).

- [ ] **Step 3: Write the doc**

Add near the top of `references/finding-template.md` (after the Depth-tiers section) three subsections and amend the tier note. Content (concise, matching the rendered views):

```markdown
## Triage line (skim layer — render first)
One row per finding, risk-ordered, real leads (needs-runtime + higher risk) above dep CVEs:
`ID · Risk · what (one clause of message) · file:line · status (confirmed | needs-runtime) · next action`.
A reader opens this first and expands into the detail views below on demand.

## NDT-view (needs-deployment-testing findings)
Condensed, always labeled **needs runtime proof**, never described as confirmed. Bindings:
| Part | Finding fields |
|---|---|
| What | `message`, `file:line` |
| Source-side chain | `dataflow` |
| Preconditions (out-of-repo barrier) | `preconditions` |
| Runtime test | `runtime_test.objective` + `expected_signal.secure/insecure` |
Runnable payloads + telemetry live in `redteam-plan.md`; the view links there.

## Dep-view (`cls == deps`)
Dependency findings do not use the source-flow sections. Bindings:
| Part | Finding fields |
|---|---|
| Package | `evidence` (`package@version`) |
| Advisory | `rule_id` / `evidence_sources` (OSV id) |
| Reachability | `reachability.reachable` + `reachability.blocker` |
| Fix | bump the package to a release resolving the advisory |

Depth-tiers note: the condensed (Medium/Low) tier **renumbers 1–4** (Summary, Mechanism,
Severity, Fix) — it does not preserve the full-tier section numbers, so no gaps leak into the view.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd skills/sec-harness/helpers && uv run pytest tests/test_docs_invariants.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skills/sec-harness/references/finding-template.md skills/sec-harness/helpers/tests/test_docs_invariants.py
git commit -m "docs(template): document triage-line, NDT-view, dep-view; condensed tier renumbered"
```

---

## Self-Review

- **Spec coverage:** serializer fix (T1); dep-view + renumber (T2); NDT-view (T3); bottom-line + triage + reorder + separate NDT count (T4); template contract (T5). ✓
- **Epistemic honesty:** T3 asserts `render_ndt` never says "confirmed" + labels needs-runtime; T4 asserts NDT counted separately, never folded into confirmed severity. ✓
- **No models/evidence/go change:** all edits in `report.py`/`redteam.py`/`finding-template.md` + tests; no new Finding field. ✓
- **Determinism:** every emitter sorts (conf/ndt by -risk then id; bullets preserve input order). Golden-tested. ✓
- **Type consistency:** `render_ndt(f)`, `_triage_row(f, status_label, action)`, `_bullets(items)`, `_signal(d)`, dep-view branch in `render_finding` — signatures consistent across tasks + `to_markdown` call sites. ✓
- **Pre-existing golden tests:** T1/T2/T4 explicitly flag that old-format assertions must be updated to the new format (intended change, not a regression to suppress). ✓
- **Placeholder scan:** every code step carries real code; the test id substrings in T4 are flagged as fixture-dependent to adjust. ✓
