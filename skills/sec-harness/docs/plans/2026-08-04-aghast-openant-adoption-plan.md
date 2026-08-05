# aghast/OpenAnt Adoption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four independently-scoped capabilities to `skills/sec-harness/`, inspired by
aghast/OpenAnt but re-implemented natively: (B) a formal `Finding` JSON schema wired into
`findings_gate.py`, (D) deterministic entry-point detection in the Tier-1 graph substrate,
(A) in-repo custom check bundles routed through the existing investigate/gate pipeline, and
(C) a prompt-only anti-hallucination guard for multi-candidate investigate worklists.

**Architecture:** Each piece is a small, focused stdlib-only module under
`helpers/sec_harness/`, wired into one existing integration point (`findings_gate.py`,
`graph.py`'s `build_tier1`, `SKILL.md`'s Phase 2-3 orchestration, `agents/investigate.md`).
No new agent types, no new phases, no runtime dependencies.

**Tech Stack:** Python 3.13 stdlib only (`json`, `re`, `pathlib`, `dataclasses`); `pytest` for
tests; no third-party packages.

## Global Constraints

- Scope is `skills/sec-harness/` only. Never touch `go/` (parallel Go-conversion workstream).
- The core is stdlib-only by design — no new runtime dependency in `pyproject.toml`.
- Work on branch `skill-aghast-openant-adoption-20260804` (current branch). Never commit to `main`.
- Stage explicit paths only (`git add skills/sec-harness/<path>`) — never `git add -A`/`-A`/`.`.
  Run `git status` before every commit to confirm nothing from `go/` is staged.
- `helpers/sec_harness/models.py` and `helpers/sec_harness/evidence.py` are the frozen
  Go-parity contract (see root `CLAUDE.md`) — this plan does not modify either file.
- Every task's test file lives under `helpers/tests/`; run via `uv run pytest <path> -v` from
  `skills/sec-harness/helpers/`.
- Lint after each task: `uv run ruff check sec_harness/ tests/` (line length 100).
- `references/*.schema.json` files use two existing precedent styles (confirmed by reading
  both): `scan-profile.schema.json` (draft-07-ish, no `additionalProperties` restriction) and
  `fix-disposition.schema.json` (2020-12 `$schema`, `enum` fields, `"additionalProperties": false`).
  `finding.schema.json` (Task 2) follows the `scan-profile.schema.json` style (no
  `additionalProperties` restriction) because `Finding.from_dict` is documented to tolerate
  unknown keys for forward-compat (`models.py:130-132`) — a strict schema would contradict that.

---

### Task 1: `sec_harness/schema.py` — minimal JSON-Schema-subset validator

**Files:**
- Create: `skills/sec-harness/helpers/sec_harness/schema.py`
- Test: `skills/sec-harness/helpers/tests/test_schema.py`

**Interfaces:**
- Produces: `validate(data: dict, schema: dict) -> list[str]` — the only public entry point.
  Returns human-readable error strings (empty list = valid). Consumed by Task 4
  (`findings_gate.py`).

**Background:** Grepping the codebase (`grep -rn "schema.json" helpers/sec_harness/*.py
helpers/tests/*.py`) turns up exactly one hit —
`tests/test_fix_and_gates.py::test_disposition_schema_exists_and_matches_enums` — and that test
only checks `schema["properties"]["completeness_tier"]["enum"]` matches a code constant; it
never validates an instance dict. There is no existing schema-validation engine anywhere in
this codebase to reuse. This module is the first one, supporting the subset of JSON Schema this
repo's three existing schema files actually use: `type` (string or list-of-strings for
nullable), `enum`, `required`, `items` (for arrays), `properties` (for nested objects).

- [ ] **Step 1: Write the failing tests**

```python
# skills/sec-harness/helpers/tests/test_schema.py
from sec_harness.schema import validate


def test_accepts_valid_flat_object():
    schema = {
        "type": "object",
        "required": ["id", "count"],
        "properties": {
            "id": {"type": "string"},
            "count": {"type": "integer"},
        },
    }
    assert validate({"id": "a", "count": 3}, schema) == []


def test_flags_missing_required_field():
    schema = {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
    errors = validate({}, schema)
    assert any("id" in e and "required" in e for e in errors)


def test_flags_wrong_type():
    schema = {"type": "object", "properties": {"count": {"type": "integer"}}}
    errors = validate({"count": "not-a-number"}, schema)
    assert any("count" in e for e in errors)


def test_nullable_type_accepts_null_and_typed_value():
    schema = {"type": "object", "properties": {"score": {"type": ["integer", "null"]}}}
    assert validate({"score": None}, schema) == []
    assert validate({"score": 5}, schema) == []
    assert validate({"score": "x"}, schema) != []


def test_enum_rejects_value_outside_set():
    schema = {"type": "object", "properties": {"status": {"enum": ["raw", "confirmed"]}}}
    assert validate({"status": "raw"}, schema) == []
    errors = validate({"status": "bogus"}, schema)
    assert any("status" in e for e in errors)


def test_array_items_are_validated():
    schema = {"type": "object", "properties": {"tags": {"type": "array", "items": {"type": "string"}}}}
    assert validate({"tags": ["a", "b"]}, schema) == []
    errors = validate({"tags": ["a", 3]}, schema)
    assert any("tags[1]" in e for e in errors)


def test_unknown_keys_not_in_properties_are_ignored():
    schema = {"type": "object", "properties": {"id": {"type": "string"}}}
    assert validate({"id": "a", "extra": "ignored"}, schema) == []


def test_top_level_non_object_is_flagged():
    schema = {"type": "object", "properties": {}}
    errors = validate("not-a-dict", schema)
    assert errors and "object" in errors[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run (from `skills/sec-harness/helpers/`): `uv run pytest tests/test_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'sec_harness.schema'` (or import error).

- [ ] **Step 3: Write the minimal implementation**

```python
# skills/sec-harness/helpers/sec_harness/schema.py
"""Minimal JSON-Schema-subset validator (stdlib only).

Supports the subset this repo's ``references/*.schema.json`` files actually use:
``type`` (string or list-of-strings for nullable fields), ``enum``, ``required``,
``items`` (array element schema), ``properties`` (nested object schema). Not a
general-purpose JSON Schema implementation — extend only when a new schema file
needs a keyword this module doesn't yet support.
"""

from __future__ import annotations

_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


def validate(data, schema: dict) -> list[str]:
    """Validate ``data`` against ``schema``.

    Args:
        data: The parsed JSON value to check (usually a dict).
        schema: A JSON-Schema-subset dict (see module docstring for supported keywords).

    Returns:
        A list of human-readable error strings; empty when ``data`` is valid.
    """
    errors: list[str] = []
    _validate_value(data, schema, "$", errors)
    return errors


def _check_type(value, type_spec, path: str, errors: list[str]) -> bool:
    types = type_spec if isinstance(type_spec, list) else [type_spec]
    py_types = tuple(_TYPE_MAP[t] for t in types)
    if not isinstance(value, py_types):
        type_names = "|".join(types)
        errors.append(f"{path}: expected type {type_names}, got {type(value).__name__}")
        return False
    return True


def _validate_value(value, prop_schema: dict, path: str, errors: list[str]) -> None:
    if "type" in prop_schema:
        if not _check_type(value, prop_schema["type"], path, errors):
            return
    if "enum" in prop_schema and value not in prop_schema["enum"]:
        errors.append(f"{path}: value {value!r} not in enum {prop_schema['enum']}")
    if isinstance(value, dict):
        _validate_object_fields(value, prop_schema, path, errors)
    if isinstance(value, list) and "items" in prop_schema:
        for i, item in enumerate(value):
            _validate_value(item, prop_schema["items"], f"{path}[{i}]", errors)


def _validate_object_fields(data: dict, schema: dict, path: str, errors: list[str]) -> None:
    for key in schema.get("required", []):
        if key not in data:
            errors.append(f"{path}.{key}: missing required field")
    properties = schema.get("properties", {})
    for key, prop_schema in properties.items():
        if key in data:
            _validate_value(data[key], prop_schema, f"{path}.{key}", errors)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_schema.py -v`
Expected: 8 passed.

- [ ] **Step 5: Lint**

Run: `uv run ruff check sec_harness/schema.py tests/test_schema.py`
Expected: no findings.

- [ ] **Step 6: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/schema.py skills/sec-harness/helpers/tests/test_schema.py
git status
git commit -m "feat(schema): add minimal JSON-Schema-subset validator"
```

---

### Task 2: `references/finding.schema.json` — formal Finding schema

**Files:**
- Create: `skills/sec-harness/references/finding.schema.json`
- Test: `skills/sec-harness/helpers/tests/test_finding_schema.py`

**Interfaces:**
- Consumes: `sec_harness.schema.validate` (Task 1).
- Produces: the schema file itself, loaded by Task 4's `findings_gate.py` wiring.

**Background:** The exact field set and defaults come from `Finding` in
`helpers/sec_harness/models.py:89-117`. Fields with **no dataclass default** —
`id, rule_id, cls, status, severity, file, line, message` — are the schema's `required` list;
this was cross-checked against `helpers/fixtures/golden_raw_finding.json` (the fixture
`test_golden_raw_finding_valid` in `test_findings_gate.py` asserts validates cleanly), which
omits every field that has a dataclass default (`fingerprint`, `priority`, `cvss_vector`,
`evidence_sources`, `asvs_ids`, `codeguard_ids`, `completeness_tier`, `runtime_disposition`,
`runtime_test`, `preconditions`, `reachability`, `judge_verdict`, `runtime_dependent`) —
confirming those must NOT be required. `severity` enum values come from the `Severity` enum
(`info`, `low`, `medium`, `high`, `critical` — `informational` is a `FindingStatus` value, not a
`Severity` value). `status` enum values come from `FindingStatus`, including the hyphenated
`needs-deployment-testing`.

- [ ] **Step 1: Write the failing tests**

```python
# skills/sec-harness/helpers/tests/test_finding_schema.py
import json
from pathlib import Path

from sec_harness.schema import validate

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "references" / "finding.schema.json"
GOLDEN_PATH = Path(__file__).parent.parent / "fixtures" / "golden_raw_finding.json"


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def test_schema_file_exists_and_parses():
    schema = _schema()
    assert schema["type"] == "object"


def test_golden_fixture_validates_cleanly():
    data = json.loads(GOLDEN_PATH.read_text())
    assert validate(data, _schema()) == []


def test_required_fields_match_finding_dataclass_no_defaults():
    schema = _schema()
    assert set(schema["required"]) == {
        "id", "rule_id", "cls", "status", "severity", "file", "line", "message",
    }


def test_missing_required_field_is_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    del data["rule_id"]
    errors = validate(data, _schema())
    assert any("rule_id" in e for e in errors)


def test_bad_severity_enum_is_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    data["severity"] = "informational"
    errors = validate(data, _schema())
    assert any("severity" in e for e in errors)


def test_bad_status_enum_is_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    data["status"] = "not-a-real-status"
    errors = validate(data, _schema())
    assert any("status" in e for e in errors)


def test_hyphenated_needs_deployment_testing_status_is_valid():
    data = json.loads(GOLDEN_PATH.read_text())
    data["status"] = "needs-deployment-testing"
    assert validate(data, _schema()) == []


def test_wrong_type_for_line_is_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    data["line"] = "eighteen"
    errors = validate(data, _schema())
    assert any("line" in e for e in errors)


def test_unknown_extra_key_is_not_flagged():
    data = json.loads(GOLDEN_PATH.read_text())
    data["some_future_field"] = "value"
    assert validate(data, _schema()) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_finding_schema.py -v`
Expected: FAIL — `finding.schema.json` does not exist (`FileNotFoundError`).

- [ ] **Step 3: Write the schema file**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["id", "rule_id", "cls", "status", "severity", "file", "line", "message"],
  "properties": {
    "id": {"type": "string"},
    "rule_id": {"type": "string"},
    "cls": {"type": "string"},
    "status": {
      "type": "string",
      "enum": [
        "candidate", "raw", "rejected", "confirmed", "fixed",
        "duplicate", "stale", "informational", "needs-deployment-testing"
      ]
    },
    "severity": {
      "type": "string",
      "enum": ["info", "low", "medium", "high", "critical"]
    },
    "file": {"type": "string"},
    "line": {"type": "integer"},
    "message": {"type": "string"},
    "dataflow": {"type": "array", "items": {"type": "string"}},
    "evidence": {"type": "string"},
    "evidence_sources": {"type": "array", "items": {"type": "string"}},
    "risk_score": {"type": ["integer", "number", "null"]},
    "verification": {"type": ["string", "null"]},
    "patch_diff": {"type": ["string", "null"]},
    "discovery_sha": {"type": ["string", "null"]},
    "duplicate_of": {"type": ["string", "null"]},
    "history": {"type": "array", "items": {"type": "object"}},
    "fingerprint": {"type": ["string", "null"]},
    "priority": {"type": ["string", "null"]},
    "cvss_vector": {"type": ["string", "null"]},
    "asvs_ids": {"type": "array", "items": {"type": "string"}},
    "codeguard_ids": {"type": "array", "items": {"type": "string"}},
    "completeness_tier": {"type": ["string", "null"]},
    "runtime_disposition": {"type": ["string", "null"]},
    "runtime_test": {"type": ["object", "null"]},
    "preconditions": {"type": "array", "items": {"type": "string"}},
    "reachability": {"type": ["object", "null"]},
    "judge_verdict": {"type": ["string", "null"]},
    "runtime_dependent": {"type": "boolean"}
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_finding_schema.py -v`
Expected: 9 passed.

- [ ] **Step 5: Commit**

The `references/` path is checked into the repo (not under any `docs/` ignore rule), so no
force-add is needed here — verify with `git status` before staging.

```bash
git add skills/sec-harness/references/finding.schema.json skills/sec-harness/helpers/tests/test_finding_schema.py
git status
git commit -m "feat(schema): add formal finding.schema.json"
```

---

### Task 3: Confirm `Finding.from_dict` still round-trips a schema-valid dict (regression guard)

**Files:**
- Test: `skills/sec-harness/helpers/tests/test_finding_schema.py` (extend from Task 2)

**Interfaces:**
- Consumes: `Finding.from_dict`/`Finding.to_dict` (`sec_harness.models`, unchanged), the golden
  fixture, `finding.schema.json` (Task 2).

This task exists to lock in the coupling between the new schema and the frozen `Finding`
contract before Task 4 wires them together — it must never regress even though `models.py`
itself is off-limits for edits in this plan.

- [ ] **Step 1: Write the failing test**

```python
# appended to skills/sec-harness/helpers/tests/test_finding_schema.py
from sec_harness.models import Finding


def test_every_finding_to_dict_field_validates_against_schema():
    f = Finding(
        id="F-0001", rule_id="r", cls="sqli", status_="raw", severity="high",
        file="a.py", line=1, message="m",
    ) if False else None  # placeholder guard removed below
```

Replace the above with the real test (no placeholder committed):

```python
# appended to skills/sec-harness/helpers/tests/test_finding_schema.py
from sec_harness.models import Finding, FindingStatus, Severity


def test_default_finding_to_dict_validates_against_schema():
    f = Finding(
        id="F-0001",
        rule_id="test-rule",
        cls="sqli",
        status=FindingStatus.RAW,
        severity=Severity.HIGH,
        file="a.py",
        line=1,
        message="m",
    )
    assert validate(f.to_dict(), _schema()) == []
```

- [ ] **Step 2: Run test to verify it fails or passes as expected**

Run: `uv run pytest tests/test_finding_schema.py::test_default_finding_to_dict_validates_against_schema -v`
Expected: this should PASS immediately since Task 2's schema was built from the dataclass
fields — it is a regression guard, not new functionality. If it fails, the schema (Task 2) has
a field mismatch and must be corrected before proceeding; re-run after fixing.

- [ ] **Step 3: Commit**

```bash
git add skills/sec-harness/helpers/tests/test_finding_schema.py
git status
git commit -m "test(schema): lock Finding.to_dict output to finding.schema.json"
```

---

### Task 4: Wire schema validation into `findings_gate.py`

**Files:**
- Modify: `skills/sec-harness/helpers/sec_harness/findings_gate.py:14-59` (the `validate_findings` function)
- Test: `skills/sec-harness/helpers/tests/test_findings_gate.py` (extend)

**Interfaces:**
- Consumes: `sec_harness.schema.validate` (Task 1), `references/finding.schema.json` (Task 2).
- Produces: no signature change to `validate_findings(ws) -> list[str]` — only additive error
  messages, prefixed with the finding's filename stem exactly like existing checks.

**Background:** Read `findings_gate.py` in full — `validate_findings` iterates
`ws.findings.glob("*.json")`, `json.loads`-parses each, then does 4 hand-rolled semantic checks
(non-empty `file`, `line >= 1`, `dataflow` is a list, tool-receipt requirement for
confirmed/fixed) before calling `Finding.from_dict`. This task inserts schema validation on the
raw parsed dict, additive to (not replacing) those checks, following the file's existing
per-finding error-prefixing convention (`f"{p.stem}: ..."`).

- [ ] **Step 1: Write the failing tests**

```python
# appended to skills/sec-harness/helpers/tests/test_findings_gate.py

def test_schema_violation_is_flagged_with_finding_id(tmp_path):
    ws = _ws(tmp_path)
    bad = _good().to_dict()
    bad["severity"] = "not-a-real-severity"
    (ws.findings / f"{bad['id']}.json").write_text(json.dumps(bad))
    errs = validate_findings(ws)
    assert any(bad["id"] in e and "severity" in e for e in errs)


def test_schema_valid_finding_produces_no_schema_errors(tmp_path):
    ws = _ws(tmp_path)
    good = _good().to_dict()
    (ws.findings / f"{good['id']}.json").write_text(json.dumps(good))
    errs = validate_findings(ws)
    assert errs == []
```

Check the existing test file's imports/fixtures first (`_ws`, `_good`, `json` import) — reuse
them exactly as already defined; do not redefine.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_findings_gate.py -k schema -v`
Expected: FAIL — `test_schema_violation_is_flagged_with_finding_id` fails because no schema
check exists yet (the bad severity currently only surfaces once `Finding.from_dict` raises,
with a different, non-schema-prefixed message, or not at all depending on enum coercion).

- [ ] **Step 3: Write the minimal implementation**

Add near the top of `findings_gate.py` (alongside existing imports):

```python
import json as _json  # only if json isn't already imported under this name — reuse existing import if present
from pathlib import Path

from sec_harness.schema import validate as _schema_validate

_FINDING_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "references" / "finding.schema.json"


def _load_finding_schema() -> dict:
    return _json.loads(_FINDING_SCHEMA_PATH.read_text())
```

Inside `validate_findings`, immediately after each finding's raw dict is parsed (before or
alongside the existing 4 checks, referencing the exact variable name already used for the
parsed dict in that loop — read the current loop body first to match it exactly), add:

```python
schema_errors = _schema_validate(data, _load_finding_schema())
errors.extend(f"{p.stem}: {e}" for e in schema_errors)
```

Do not remove or reorder any existing check — this is additive. `_load_finding_schema()` reads
the file fresh per call; given `findings_gate` runs once per campaign phase over a workspace's
findings (typically tens, not thousands), this is not a hot path — no caching needed (YAGNI).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_findings_gate.py -v`
Expected: ALL tests in the file pass, including the two new ones and all 9 pre-existing ones
(`test_accepts_good_finding`, `test_flags_bad_line_and_file`, `test_flags_unparseable`,
`test_golden_raw_finding_valid`, the two `duplicate_of`-consistency tests, the tool-receipt
tests, and the `needs-deployment-testing`-exempt test) — confirm none regressed.

- [ ] **Step 5: Lint**

Run: `uv run ruff check sec_harness/findings_gate.py tests/test_findings_gate.py`
Expected: no findings.

- [ ] **Step 6: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/findings_gate.py skills/sec-harness/helpers/tests/test_findings_gate.py
git status
git commit -m "feat(gate): validate every finding against finding.schema.json"
```

---

### Task 5: `sec_harness/entrypoints.py` — deterministic entry-point classification

**Files:**
- Create: `skills/sec-harness/helpers/sec_harness/entrypoints.py`
- Test: `skills/sec-harness/helpers/tests/test_entrypoints.py`

**Interfaces:**
- Produces: `classify_entry_point(lang: str, all_lines: list[str], start: int, end: int) -> str | None`
  — consumed by Task 6 (`graph.py`'s `build_tier1`).

**Background:** `structural_index.get_function_boundary` (read in full,
`structural_index.py:48-93`) returns a 1-indexed inclusive `(start, end)` span beginning exactly
at the `def`/`function` line — it never includes a preceding decorator line. Python route
decorators (`@app.route(...)`) sit on the line(s) immediately above `start`, so Python
classification must look upward for contiguous `@`-prefixed lines before pattern-matching.
`graph.py`'s `_lang_of` (`graph.py:145-148`) returns the file extension without its dot (`py`,
`js`, `ts`, `jsx`, `tsx`, `go`, `rb`, `php`, plus others this module does not classify).

- [ ] **Step 1: Write the failing tests**

```python
# skills/sec-harness/helpers/tests/test_entrypoints.py
from sec_harness.entrypoints import classify_entry_point


def test_python_route_decorator_detected():
    lines = [
        "@app.route('/users/<id>')",
        "def get_user(id):",
        "    return db.fetch(id)",
    ]
    reason = classify_entry_point("py", lines, start=2, end=3)
    assert reason is not None
    assert "route" in reason


def test_python_non_contiguous_decorator_not_pulled_in():
    lines = [
        "@app.route('/users')",
        "",
        "def unrelated():",
        "    pass",
        "",
        "def internal_helper(x):",
        "    return x + 1",
    ]
    # internal_helper starts at line 6; the decorator two lines above it is
    # separated by a blank line and a different def, so it must NOT attach.
    reason = classify_entry_point("py", lines, start=6, end=7)
    assert reason is None


def test_python_user_input_access_detected():
    lines = [
        "def handler():",
        "    uid = request.args.get('id')",
        "    return uid",
    ]
    reason = classify_entry_point("py", lines, start=1, end=3)
    assert reason is not None
    assert "user-input" in reason


def test_python_cli_arg_detected():
    lines = [
        "def main():",
        "    target = sys.argv[1]",
        "    return target",
    ]
    reason = classify_entry_point("py", lines, start=1, end=3)
    assert reason is not None
    assert "cli-arg" in reason


def test_python_env_var_detected():
    lines = [
        "def load_config():",
        "    key = os.environ['API_KEY']",
        "    return key",
    ]
    reason = classify_entry_point("py", lines, start=1, end=3)
    assert reason is not None
    assert "env-var" in reason


def test_python_internal_function_not_flagged():
    lines = [
        "def add(a, b):",
        "    return a + b",
    ]
    assert classify_entry_point("py", lines, start=1, end=2) is None


def test_go_route_handler_detected():
    lines = [
        "func handler(w http.ResponseWriter, r *http.Request) {",
        "    router.GET(\"/users\", handler)",
        "}",
    ]
    reason = classify_entry_point("go", lines, start=1, end=3)
    assert reason is not None
    assert "route" in reason


def test_go_env_var_detected():
    lines = [
        "func loadConfig() string {",
        "    return os.Getenv(\"API_KEY\")",
        "}",
    ]
    reason = classify_entry_point("go", lines, start=1, end=3)
    assert reason is not None
    assert "env-var" in reason


def test_ruby_params_access_detected():
    lines = [
        "def show",
        "  id = params[:id]",
        "  id",
        "end",
    ]
    reason = classify_entry_point("rb", lines, start=1, end=4)
    assert reason is not None
    assert "user-input" in reason


def test_php_superglobal_detected():
    lines = [
        "function getUser() {",
        "    $id = $_GET['id'];",
        "    return $id;",
        "}",
    ]
    reason = classify_entry_point("php", lines, start=1, end=4)
    assert reason is not None
    assert "user-input" in reason


def test_js_express_route_detected():
    lines = [
        "app.get('/users/:id', function(req, res) {",
        "    res.send(req.params.id);",
        "});",
    ]
    reason = classify_entry_point("js", lines, start=1, end=3)
    assert reason is not None
    assert "route" in reason


def test_ts_process_argv_detected():
    lines = [
        "function main() {",
        "    const target = process.argv[2];",
        "    return target;",
        "}",
    ]
    reason = classify_entry_point("ts", lines, start=1, end=4)
    assert reason is not None
    assert "cli-arg" in reason


def test_unsupported_language_returns_none():
    lines = ["public class Main {", "    void run() {}", "}"]
    assert classify_entry_point("java", lines, start=1, end=3) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_entrypoints.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sec_harness.entrypoints'`.

- [ ] **Step 3: Write the minimal implementation**

```python
# skills/sec-harness/helpers/sec_harness/entrypoints.py
"""Deterministic, regex-based entry-point classification for the Tier-1 graph substrate.

Flags a function/method definition as an external entry point when its body (or, for
Python, its immediately preceding decorator block) matches a route-registration,
user-input-access, CLI-argument, or environment-variable pattern for its language. This
is LLM-free and always computed as part of Tier-1 (see ``graph.build_tier1``) — it gives
``no_path``/``attacker_controls`` a deterministic seed set instead of relying solely on
the LLM-asserted ``scan-profile.json`` ``attack_surface``.
"""

from __future__ import annotations

import re

_ROUTE_PY = re.compile(r"@(?:\w+\.)?(?:route|get|post|put|delete|patch)\s*\(", re.IGNORECASE)
_USER_INPUT_PY = re.compile(r"\brequest\.(?:args|form|json|data|GET|POST|values|files|cookies|headers)\b")
_CLI_ARG_PY = re.compile(r"\bsys\.argv\b|\badd_argument\s*\(")
_ENV_PY = re.compile(r"\bos\.environ\[|\bos\.getenv\(")

_ROUTE_GO = re.compile(r"\.(?:GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc)\s*\(")
_USER_INPUT_GO = re.compile(r"\.URL\.Query\(\)|\.FormValue\(|\.Query\(|\.Param\(")
_CLI_ARG_GO = re.compile(r"\bos\.Args\b|\bflag\.(?:String|Int|Bool)\(")
_ENV_GO = re.compile(r"\bos\.Getenv\(")

_ROUTE_RB = re.compile(r"^\s*(?:get|post|put|patch|delete)\s+['\"]", re.MULTILINE)
_USER_INPUT_RB = re.compile(r"\bparams\[|\brequest\.(?:GET|POST|body)\b")
_CLI_ARG_RB = re.compile(r"\bARGV\b")
_ENV_RB = re.compile(r"\bENV\[")

_ROUTE_PHP = re.compile(r"Route::(?:get|post|put|patch|delete)\s*\(", re.IGNORECASE)
_USER_INPUT_PHP = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b")
_CLI_ARG_PHP = re.compile(r"\$argv\b")
_ENV_PHP = re.compile(r"\bgetenv\(|\$_ENV\[")

_ROUTE_JS = re.compile(r"\.(?:get|post|put|patch|delete)\s*\(\s*['\"]|@(?:Get|Post|Put|Patch|Delete)\s*\(")
_USER_INPUT_JS = re.compile(r"\breq\.(?:query|body|params|headers|cookies)\b")
_CLI_ARG_JS = re.compile(r"\bprocess\.argv\b")
_ENV_JS = re.compile(r"\bprocess\.env\.")

_ROUTE_REASON = "route-decorator: external HTTP route/handler registration"
_USER_INPUT_REASON = "user-input-access: reads request data directly"
_CLI_ARG_REASON = "cli-arg: reads command-line arguments"
_ENV_REASON = "env-var-access: reads environment variables"

_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    "py": [
        (_ROUTE_PY, _ROUTE_REASON),
        (_USER_INPUT_PY, _USER_INPUT_REASON),
        (_CLI_ARG_PY, _CLI_ARG_REASON),
        (_ENV_PY, _ENV_REASON),
    ],
    "go": [
        (_ROUTE_GO, _ROUTE_REASON),
        (_USER_INPUT_GO, _USER_INPUT_REASON),
        (_CLI_ARG_GO, _CLI_ARG_REASON),
        (_ENV_GO, _ENV_REASON),
    ],
    "rb": [
        (_ROUTE_RB, _ROUTE_REASON),
        (_USER_INPUT_RB, _USER_INPUT_REASON),
        (_CLI_ARG_RB, _CLI_ARG_REASON),
        (_ENV_RB, _ENV_REASON),
    ],
    "php": [
        (_ROUTE_PHP, _ROUTE_REASON),
        (_USER_INPUT_PHP, _USER_INPUT_REASON),
        (_CLI_ARG_PHP, _CLI_ARG_REASON),
        (_ENV_PHP, _ENV_REASON),
    ],
}
for _js_lang in ("js", "ts", "jsx", "tsx"):
    _PATTERNS[_js_lang] = [
        (_ROUTE_JS, _ROUTE_REASON),
        (_USER_INPUT_JS, _USER_INPUT_REASON),
        (_CLI_ARG_JS, _CLI_ARG_REASON),
        (_ENV_JS, _ENV_REASON),
    ]


def _decorator_prefix(all_lines: list[str], start: int) -> str:
    """Collect contiguous ``@``-prefixed lines immediately above a 1-indexed ``start`` line.

    Args:
        all_lines: The file's lines (0-indexed list, as from ``str.splitlines()``).
        start: The 1-indexed line where the definition itself begins.

    Returns:
        The contiguous decorator lines directly above ``start``, in original order,
        joined by newlines (empty string if none).
    """
    collected: list[str] = []
    i = start - 2  # 0-indexed line directly above `start`
    while i >= 0 and all_lines[i].strip().startswith("@"):
        collected.append(all_lines[i])
        i -= 1
    return "\n".join(reversed(collected))


def classify_entry_point(lang: str, all_lines: list[str], start: int, end: int) -> str | None:
    """Classify a definition's line span as an entry point, or return ``None``.

    Args:
        lang: Language tag as returned by ``graph._lang_of`` (extension without the dot).
        all_lines: The file's lines (0-indexed list, as from ``str.splitlines()``).
        start: 1-indexed inclusive start line of the definition (from
            ``structural_index.get_function_boundary``).
        end: 1-indexed inclusive end line of the definition.

    Returns:
        A reason string naming the matched category (route-decorator / user-input-access /
        cli-arg / env-var-access), or ``None`` if no pattern matched or the language has no
        pattern table.
    """
    patterns = _PATTERNS.get(lang)
    if not patterns:
        return None
    body = "\n".join(all_lines[start - 1:end])
    if lang == "py":
        prefix = _decorator_prefix(all_lines, start)
        if prefix:
            body = prefix + "\n" + body
    for pattern, reason in patterns:
        if pattern.search(body):
            return reason
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_entrypoints.py -v`
Expected: 13 passed.

- [ ] **Step 5: Lint**

Run: `uv run ruff check sec_harness/entrypoints.py tests/test_entrypoints.py`
Expected: no findings.

- [ ] **Step 6: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/entrypoints.py skills/sec-harness/helpers/tests/test_entrypoints.py
git status
git commit -m "feat(graph): add deterministic entry-point classification"
```

---

### Task 6: Wire entry-point classification into `graph.build_tier1`

**Files:**
- Modify: `skills/sec-harness/helpers/sec_harness/graph.py:151-211` (`build_tier1`), plus a new
  `entry_point_nodes` function
- Test: `skills/sec-harness/helpers/tests/test_graph.py` (extend)

**Interfaces:**
- Consumes: `sec_harness.entrypoints.classify_entry_point` (Task 5).
- Produces: `Node.attrs["is_entry_point"]: bool` and (when true) `Node.attrs["entry_point_reason"]: str`
  on every symbol node; `entry_point_nodes(graph: Graph) -> list[Node]`.

**Background:** `build_tier1`'s existing per-file loop (`graph.py:170-181`) reads each source
file's definitions via `structural_index.list_definitions`, builds each `Node`, and separately
computes `structural_index.get_function_boundary` to populate the `bodies` list used later for
call-edge detection. This task reads the file's lines once per file (reusing them for
classification), computes `start`/`end` at node-construction time (moved up from its current
position), and sets `is_entry_point`/`entry_point_reason` on every node **unconditionally** —
consistent with `CLAUDE.md`'s hard rule that "the Tier-1 substrate is always built, never behind
a flag." The existing per-body file re-read at `graph.py:195` for call-edge detection is left
untouched (out of scope — a separate optimization, not requested).

- [ ] **Step 1: Write the failing test**

First inspect the existing fixture directory `tests/fixtures/graph_target/` (used by
`test_build_tier1_emits_nodes_and_call_edge`) to see its exact file layout before adding to it —
read `app/api.py` there. Add a new fixture route-style function so the entry-point test has
something concrete to assert on:

```python
# skills/sec-harness/helpers/tests/fixtures/graph_target/app/api.py
# (append to the existing file — do NOT overwrite; read it first and add below the
# existing `handler` definition so the existing call-edge test is unaffected)

@app.route('/widgets/<id>')
def get_widget(id):
    return db.run_query(id)
```

```python
# appended to skills/sec-harness/helpers/tests/test_graph.py

def test_build_tier1_flags_entry_points():
    graph = g.build_tier1(FIXTURE, sha="deadbeef")
    widget_node = graph.node("app/api.py:5:get_widget")
    assert widget_node is not None
    assert widget_node.attrs["is_entry_point"] is True
    assert "route" in widget_node.attrs["entry_point_reason"]


def test_build_tier1_does_not_flag_internal_helper():
    graph = g.build_tier1(FIXTURE, sha="deadbeef")
    db_node = graph.node("app/db.py:1:run_query")
    assert db_node is not None
    assert db_node.attrs["is_entry_point"] is False
    assert "entry_point_reason" not in db_node.attrs


def test_entry_point_nodes_returns_only_flagged_nodes():
    graph = g.build_tier1(FIXTURE, sha="deadbeef")
    flagged = g.entry_point_nodes(graph)
    assert all(n.attrs.get("is_entry_point") for n in flagged)
    assert any(n.id == "app/api.py:5:get_widget" for n in flagged)
```

Note: the exact line number in `app/api.py:5:get_widget` depends on the existing fixture file's
current line count — before writing this test, `Read` the fixture file to confirm the line
number the new `get_widget` definition lands on, and use that number.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_graph.py -k entry_point -v`
Expected: FAIL — `KeyError: 'is_entry_point'` (the key doesn't exist on nodes yet).

- [ ] **Step 3: Write the minimal implementation**

Add the import at the top of `graph.py`:

```python
from sec_harness import entrypoints, structural_index
```

(replace the existing `from sec_harness import structural_index` line with this combined
import, or add `entrypoints` alongside it — match whatever import-grouping style the file
already uses).

Replace the per-file loop body in `build_tier1` (`graph.py:170-181`):

```python
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in _SOURCE_EXTS:
            continue
        rel = path.relative_to(root).as_posix()
        lang = _lang_of(rel)
        file_lines = path.read_text().splitlines()
        for name, line in structural_index.list_definitions(path):
            node_id = f"{rel}:{line}:{name}"
            start, end = structural_index.get_function_boundary(path, line)
            reason = entrypoints.classify_entry_point(lang, file_lines, start, end)
            attrs = {"lang": lang, "unresolvable": False, "is_entry_point": reason is not None}
            if reason is not None:
                attrs["entry_point_reason"] = reason
            nodes.append(Node(node_id, "symbol", rel, line, name, attrs))
            by_name.setdefault(name, []).append(node_id)
            bodies.append((node_id, str(path), start, end))
```

Add a new function after `is_unresolvable` (or anywhere alongside the other node-query
helpers such as `symbol_at`):

```python
def entry_point_nodes(graph: Graph) -> list[Node]:
    """Return all nodes flagged as entry points during Tier-1 build.

    Args:
        graph: The substrate to query.

    Returns:
        Nodes whose ``attrs["is_entry_point"]`` is true, in graph node order.
    """
    return [n for n in graph.nodes if n.attrs.get("is_entry_point")]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_graph.py -v`
Expected: ALL tests pass, including the pre-existing `test_build_tier1_emits_nodes_and_call_edge`
(unaffected — only additive attrs) and the 3 new entry-point tests.

- [ ] **Step 5: Lint**

Run: `uv run ruff check sec_harness/graph.py tests/test_graph.py`
Expected: no findings.

- [ ] **Step 6: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/graph.py skills/sec-harness/helpers/tests/test_graph.py skills/sec-harness/helpers/tests/fixtures/graph_target/app/api.py
git status
git commit -m "feat(graph): flag entry-point nodes during Tier-1 build"
```

---

### Task 7: `sec_harness/custom_checks.py` — in-repo custom check bundle discovery

**Files:**
- Create: `skills/sec-harness/helpers/sec_harness/custom_checks.py`
- Test: `skills/sec-harness/helpers/tests/test_custom_checks.py`

**Interfaces:**
- Produces:
  - `CustomCheck` dataclass: `check_id: str`, `name: str`, `severity: str`,
    `instructions_path: Path`, `semgrep_rule_path: Path | None = None`,
    `applicable_paths: list[str] = field(default_factory=list)`,
    `excluded_paths: list[str] = field(default_factory=list)`.
  - `discover_custom_checks(target_root: str | Path) -> list[CustomCheck]`
  - `custom_check_classes(checks: list[CustomCheck]) -> list[str]`
  - `merge_custom_check_classes(agents_to_spawn: list[str], checks: list[CustomCheck]) -> list[str]`
  - `custom_check_instructions(check: CustomCheck) -> str`
- Consumed by: Task 8 (`SKILL.md` orchestration wiring, no Python caller — this is invoked
  directly by the orchestrating agent per `SKILL.md`, the same way `reconcile_plan` is).

**Background:** Bundle location and shape per the approved design:
`.sec-harness/checks/<check-id>/<check-id>.json` (manifest: `name`, `severity`,
`instructionsFile`, optional `semgrepRule`/`applicablePaths`/`excludedPaths`) plus an
instructions file the manifest's `instructionsFile` key points to (by convention
`<check-id>.md`, but the loader must honor whatever filename the manifest specifies rather than
hardcoding it). A malformed bundle (missing manifest, invalid JSON, missing required key,
invalid severity, missing instructions file) is **skipped with a stderr warning**, matching this
codebase's existing tolerant-parsing convention (`workspace.py`'s `read_findings` skips
unparseable findings with a stderr warning rather than raising). `merge_custom_check_classes`
mirrors `partition.reconcile_plan`'s append-only semantics but cannot reuse it directly:
`reconcile_plan` only adds a class with a live SAST candidate, whereas custom checks must be
investigated even at zero prefilter hits (hunt-list-style, matching `partition.must_investigate`'s
existing "any planned class investigates regardless of candidate count" behavior).

- [ ] **Step 1: Write the failing tests**

```python
# skills/sec-harness/helpers/tests/test_custom_checks.py
import json
from pathlib import Path

from sec_harness.custom_checks import (
    CustomCheck,
    custom_check_classes,
    custom_check_instructions,
    discover_custom_checks,
    merge_custom_check_classes,
)


def _write_bundle(root: Path, check_id: str, *, manifest: dict, instructions: str = "Check for X.",
                   instructions_filename: str | None = None):
    bundle_dir = root / ".sec-harness" / "checks" / check_id
    bundle_dir.mkdir(parents=True, exist_ok=True)
    instructions_filename = instructions_filename or f"{check_id}.md"
    manifest = {**manifest, "instructionsFile": instructions_filename}
    (bundle_dir / f"{check_id}.json").write_text(json.dumps(manifest))
    (bundle_dir / instructions_filename).write_text(instructions)
    return bundle_dir


def test_no_checks_dir_returns_empty_list(tmp_path):
    assert discover_custom_checks(tmp_path) == []


def test_discovers_a_well_formed_bundle(tmp_path):
    _write_bundle(
        tmp_path, "payment-integrity",
        manifest={"name": "Payment integrity", "severity": "high"},
        instructions="Every payment endpoint must re-derive price server-side.",
    )
    checks = discover_custom_checks(tmp_path)
    assert len(checks) == 1
    check = checks[0]
    assert check.check_id == "payment-integrity"
    assert check.name == "Payment integrity"
    assert check.severity == "high"
    assert check.instructions_path.is_file()


def test_discovers_multiple_bundles_sorted_by_id(tmp_path):
    _write_bundle(tmp_path, "zzz-check", manifest={"name": "Z", "severity": "low"})
    _write_bundle(tmp_path, "aaa-check", manifest={"name": "A", "severity": "low"})
    checks = discover_custom_checks(tmp_path)
    assert [c.check_id for c in checks] == ["aaa-check", "zzz-check"]


def test_missing_manifest_skips_bundle_with_warning(tmp_path, capsys):
    bundle_dir = tmp_path / ".sec-harness" / "checks" / "broken"
    bundle_dir.mkdir(parents=True)
    (bundle_dir / "broken.md").write_text("instructions")
    checks = discover_custom_checks(tmp_path)
    assert checks == []
    assert "broken" in capsys.readouterr().err


def test_invalid_json_manifest_skips_bundle_with_warning(tmp_path, capsys):
    bundle_dir = tmp_path / ".sec-harness" / "checks" / "broken"
    bundle_dir.mkdir(parents=True)
    (bundle_dir / "broken.json").write_text("{not valid json")
    checks = discover_custom_checks(tmp_path)
    assert checks == []
    assert "broken" in capsys.readouterr().err


def test_invalid_severity_skips_bundle_with_warning(tmp_path, capsys):
    _write_bundle(tmp_path, "bad-sev", manifest={"name": "Bad", "severity": "extreme"})
    checks = discover_custom_checks(tmp_path)
    assert checks == []
    assert "bad-sev" in capsys.readouterr().err


def test_missing_instructions_file_skips_bundle_with_warning(tmp_path, capsys):
    bundle_dir = tmp_path / ".sec-harness" / "checks" / "no-instructions"
    bundle_dir.mkdir(parents=True)
    manifest = {"name": "X", "severity": "low", "instructionsFile": "no-instructions.md"}
    (bundle_dir / "no-instructions.json").write_text(json.dumps(manifest))
    checks = discover_custom_checks(tmp_path)
    assert checks == []
    assert "no-instructions" in capsys.readouterr().err


def test_semgrep_rule_path_populated_when_present(tmp_path):
    bundle_dir = _write_bundle(
        tmp_path, "with-rule", manifest={"name": "R", "severity": "medium", "semgrepRule": "with-rule.yaml"},
    )
    (bundle_dir / "with-rule.yaml").write_text("rules: []")
    checks = discover_custom_checks(tmp_path)
    assert checks[0].semgrep_rule_path == bundle_dir / "with-rule.yaml"


def test_custom_check_classes_returns_check_ids(tmp_path):
    _write_bundle(tmp_path, "check-a", manifest={"name": "A", "severity": "low"})
    _write_bundle(tmp_path, "check-b", manifest={"name": "B", "severity": "low"})
    checks = discover_custom_checks(tmp_path)
    assert custom_check_classes(checks) == ["check-a", "check-b"]


def test_merge_custom_check_classes_appends_without_duplicating():
    checks = [CustomCheck("sqli", "n", "high", Path("x"))]
    merged = merge_custom_check_classes(["sqli", "xss"], checks)
    assert merged == ["sqli", "xss"]  # sqli already planned, no duplicate


def test_merge_custom_check_classes_appends_new_class():
    checks = [CustomCheck("payment-integrity", "n", "high", Path("x"))]
    merged = merge_custom_check_classes(["sqli", "xss"], checks)
    assert merged == ["sqli", "xss", "payment-integrity"]


def test_custom_check_instructions_reads_file(tmp_path):
    _write_bundle(
        tmp_path, "payment-integrity",
        manifest={"name": "Payment integrity", "severity": "high"},
        instructions="Every payment endpoint must re-derive price server-side.",
    )
    check = discover_custom_checks(tmp_path)[0]
    assert custom_check_instructions(check) == "Every payment endpoint must re-derive price server-side."
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_custom_checks.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sec_harness.custom_checks'`.

- [ ] **Step 3: Write the minimal implementation**

```python
# skills/sec-harness/helpers/sec_harness/custom_checks.py
"""In-repo custom security-check bundle discovery.

A team encodes its own business-logic policy checks under a target repo's
``.sec-harness/checks/<check-id>/`` directory (checked in, versioned alongside the code
it describes). Each bundle is registered as an additional attack-class entry and
dispatched through the existing ``agents/investigate.md`` machinery — no separate,
lighter-weight validation path. This module only discovers and loads bundles; it does
not run them.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass
class CustomCheck:
    """One discovered custom check bundle."""

    check_id: str
    name: str
    severity: str
    instructions_path: Path
    semgrep_rule_path: Path | None = None
    applicable_paths: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)


def _validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []
    for key in ("name", "severity", "instructionsFile"):
        if not manifest.get(key):
            errors.append(f"missing required field {key!r}")
    if manifest.get("severity") is not None and manifest["severity"] not in _VALID_SEVERITIES:
        errors.append(f"severity must be one of {sorted(_VALID_SEVERITIES)}")
    return errors


def discover_custom_checks(target_root: str | Path) -> list[CustomCheck]:
    """Scan ``.sec-harness/checks/`` under ``target_root`` for custom check bundles.

    A malformed bundle (missing/invalid manifest, missing required field, invalid
    severity, missing instructions file) is skipped with a warning printed to stderr —
    it never raises, so one broken bundle cannot stop discovery of the rest.

    Args:
        target_root: The target repo's root directory.

    Returns:
        Discovered bundles, sorted by ``check_id``. Empty list if no checks directory
        exists.
    """
    checks_dir = Path(target_root) / ".sec-harness" / "checks"
    if not checks_dir.is_dir():
        return []

    out: list[CustomCheck] = []
    for bundle_dir in sorted(p for p in checks_dir.iterdir() if p.is_dir()):
        check_id = bundle_dir.name
        manifest_path = bundle_dir / f"{check_id}.json"
        if not manifest_path.is_file():
            print(f"custom_checks: skipping {check_id}: missing {manifest_path.name}", file=sys.stderr)
            continue
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"custom_checks: skipping {check_id}: invalid JSON ({exc})", file=sys.stderr)
            continue

        errors = _validate_manifest(manifest)
        if errors:
            print(f"custom_checks: skipping {check_id}: {'; '.join(errors)}", file=sys.stderr)
            continue

        instructions_path = bundle_dir / manifest["instructionsFile"]
        if not instructions_path.is_file():
            print(
                f"custom_checks: skipping {check_id}: instructions file "
                f"{manifest['instructionsFile']} not found",
                file=sys.stderr,
            )
            continue

        semgrep_rule_path = None
        if manifest.get("semgrepRule"):
            candidate = bundle_dir / manifest["semgrepRule"]
            if candidate.is_file():
                semgrep_rule_path = candidate
            else:
                print(
                    f"custom_checks: {check_id}: semgrepRule {manifest['semgrepRule']} "
                    "not found, ignoring",
                    file=sys.stderr,
                )

        out.append(
            CustomCheck(
                check_id=check_id,
                name=manifest["name"],
                severity=manifest["severity"],
                instructions_path=instructions_path,
                semgrep_rule_path=semgrep_rule_path,
                applicable_paths=list(manifest.get("applicablePaths", [])),
                excluded_paths=list(manifest.get("excludedPaths", [])),
            )
        )
    return out


def custom_check_classes(checks: list[CustomCheck]) -> list[str]:
    """Return the attack-class keys (``check_id``s) for a list of discovered checks."""
    return [c.check_id for c in checks]


def merge_custom_check_classes(agents_to_spawn: list[str], checks: list[CustomCheck]) -> list[str]:
    """Append custom-check classes not already in ``agents_to_spawn``.

    Args:
        agents_to_spawn: The profile's planned attack-class list.
        checks: Discovered custom checks (see :func:`discover_custom_checks`).

    Returns:
        ``agents_to_spawn`` followed by any custom-check ids not already present.
        Never removes or reorders a planned class.
    """
    existing = set(agents_to_spawn)
    extra = [c.check_id for c in checks if c.check_id not in existing]
    return list(agents_to_spawn) + extra


def custom_check_instructions(check: CustomCheck) -> str:
    """Read a custom check's instructions file content."""
    return check.instructions_path.read_text()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_custom_checks.py -v`
Expected: 13 passed.

- [ ] **Step 5: Lint**

Run: `uv run ruff check sec_harness/custom_checks.py tests/test_custom_checks.py`
Expected: no findings.

- [ ] **Step 6: Commit**

```bash
git add skills/sec-harness/helpers/sec_harness/custom_checks.py skills/sec-harness/helpers/tests/test_custom_checks.py
git status
git commit -m "feat(custom-checks): add in-repo custom check bundle discovery"
```

---

### Task 8: Wire custom-check discovery into the orchestration playbook (`SKILL.md`)

**Files:**
- Modify: `skills/sec-harness/SKILL.md:96` (Phase order table) and `SKILL.md:191-211` (Phase 2-3 detail section)

**Interfaces:**
- Consumes: `discover_custom_checks`, `custom_check_classes`, `merge_custom_check_classes`,
  `custom_check_instructions` (Task 7).
- No Python interface produced — this task is documentation that directs the orchestrating
  agent (there is no separate `orchestrator.py` module in this repo; `CLAUDE.md` §3 states "the
  main agent orchestrates" by reading `SKILL.md` and calling helpers/agents directly).

**Background:** The existing integration point for augmenting `agents_to_spawn` post-prefilter
is `SKILL.md:96`: `agents = reconcile_plan(ws, profile.agents_to_spawn)`, called right before
"Spawn investigate agents." Custom checks must be merged the same way, and — per the design's
"Execution" bullet — each custom check's markdown instructions get appended to the standard
`agents/investigate.md` prompt when that class is a custom-check id, so the same subagent
dispatch mechanism handles both built-in and custom classes with no new agent type.

- [ ] **Step 1: Edit `SKILL.md` line 96** (Phase-order quick-reference table)

Find the existing line (quoted verbatim above in Files section) that reads:

```
...Then `demote_noise(ws)` (moves log-injection/clear-text-logging/unknown candidates to `informational`) and `agents = reconcile_plan(ws, profile.agents_to_spawn)` (routes real-security classes recon omitted). Spawn investigate agents over the reconciled `agents`; the general-triage `security-other` agent handles any residual unrouted classes.
```

Replace it with:

```
...Then `demote_noise(ws)` (moves log-injection/clear-text-logging/unknown candidates to `informational`), `agents = reconcile_plan(ws, profile.agents_to_spawn)` (routes real-security classes recon omitted), and `agents = merge_custom_check_classes(agents, discover_custom_checks(target))` (from `sec_harness.custom_checks`; adds any in-repo `.sec-harness/checks/` bundles the target declares). Spawn investigate agents over the reconciled `agents`; for any class that is a custom-check id, append `custom_check_instructions(check)` to the standard `agents/investigate.md` prompt after the shared `prompt-constants.md` blocks, per its check's own bundle. The general-triage `security-other` agent handles any residual unrouted classes.
```

- [ ] **Step 2: Edit `SKILL.md`'s Phase 2-3 detail section (around line 202)**

Find the existing sentence in step 2 of "Phase 2–3: Prefilter + investigation (agentic)":

```
   subagents **in ONE message** — one per
   class in `scan-profile.json` `agents_to_spawn`, each with `agents/investigate.md`
   (substituting `{{ATTACK_CLASS}}`, `{{TARGET}}`, `{{WORKSPACE}}`) and handed its
   partition — so they run concurrently.
```

Replace with:

```
   subagents **in ONE message** — one per
   class in `scan-profile.json` `agents_to_spawn` (after merging in any custom-check
   classes via `sec_harness.custom_checks.discover_custom_checks(target)` +
   `merge_custom_check_classes`), each with `agents/investigate.md`
   (substituting `{{ATTACK_CLASS}}`, `{{TARGET}}`, `{{WORKSPACE}}`) and handed its
   partition — so they run concurrently. When `{{ATTACK_CLASS}}` is a custom-check id,
   append that check's `custom_check_instructions(check)` markdown to the assembled
   prompt after the shared `prompt-constants.md` blocks (`ANTI_MANIPULATION`,
   `TOOL_TRUST`, `SEVERITY_PRECONDITION`, etc.) so it gets the same trust envelope as
   every built-in class. A custom-check candidate goes through the full existing gate
   ladder — dedupe, critic → judge → validate → trace, calibrate — exactly like any
   other finding; there is no lighter-weight path for org-authored checks.
```

- [ ] **Step 3: Verify the edited file renders sensibly**

Run: `grep -n "merge_custom_check_classes\|custom_check_instructions" SKILL.md` from
`skills/sec-harness/` — confirm both edits landed and read correctly in context (re-read the
surrounding lines).

- [ ] **Step 4: Commit**

```bash
git add skills/sec-harness/SKILL.md
git status
git commit -m "docs(skill): wire custom check discovery into orchestration playbook"
```

---

### Task 9: Section C — cross-target anti-hallucination self-check in `investigate.md`

**Files:**
- Modify: `skills/sec-harness/agents/investigate.md:76` (step 5 "Decide" of the Procedure section)

**Interfaces:** None (prompt-only change; no code, no schema, no new test — per the approved
design's own Testing section: "no automated test (prompt-only change)").

**Background:** `investigate.md:58-66` already instructs the agent to work a worklist of many
candidates in one context, explicitly naming ">~40 candidates for large buckets like xss,"
grouped by sink pattern/file, with one verdict applied to "mechanically-identical siblings."
Gate −1 (sanity/hallucination, `investigate.md:100-106`) already rejects a finding whose cited
`file:line` doesn't exist or doesn't match the described code — but it does not catch the case
where the cited location IS real and IS a genuine sink, just belongs to a *different* candidate
in the same batch (attribution swap between two similar-looking sinks processed in one pass).
This task adds an explicit self-check instruction to close that gap.

Scope decision (confirmed by reading both files in full): this instruction is **not** promoted
to `references/prompt-constants.md`. `agents/critic.md` (80 lines) and `agents/patch.md` (69
lines) both process findings one at a time in a simple loop ("For each `raw` finding" /
"For each `confirmed` finding") with no grouping/batching instruction — the batch-attribution
risk this section addresses is specific to `investigate.md`'s explicit multi-candidate grouping
instruction, which those two prompts don't share. If a future prompt introduces batched
processing, promote this instruction to `prompt-constants.md` at that time instead of
duplicating it — but do not do so speculatively now.

- [ ] **Step 1: Edit `agents/investigate.md` step 5**

Find the existing step 5 (quoted verbatim above from the file read this session):

```markdown
5. Decide:
   - **Confirmed** (a real, reachable issue that clears all gates AND survived your own
     refutation): write the finding with `status: "raw"`, a `dataflow` array of
     `"expr @ file:line"` hops from source to sink, an `evidence` snippet, a `preconditions`
     array (per SEVERITY_PRECONDITION — write it before choosing severity), and a
     one-line `message`.
```

Insert a new sub-step immediately before the existing bullet list, so step 5 reads:

```markdown
5. Decide. **Before writing `file`/`line` for candidate N, re-confirm it is candidate N's
   own cited location, not a sibling candidate's** — when triaging a grouped batch (per
   step 1's large-bucket grouping), it is easy to attribute the wrong sink line to a
   finding after reading several similar-looking sinks in sequence. Re-read the specific
   `file:line` you are about to write against the candidate's original citation before
   committing it.
   - **Confirmed** (a real, reachable issue that clears all gates AND survived your own
     refutation): write the finding with `status: "raw"`, a `dataflow` array of
     `"expr @ file:line"` hops from source to sink, an `evidence` snippet, a `preconditions`
     array (per SEVERITY_PRECONDITION — write it before choosing severity), and a
     one-line `message`.
```

(Leave every other bullet under step 5 — Refuted, Hallucinated, Runtime-dependent — exactly as
they are; only the new sentence and its lead-in are added.)

- [ ] **Step 2: Verify the edit**

Run: `grep -n "sibling candidate" skills/sec-harness/agents/investigate.md` from the repo root
— confirm exactly one match, in the expected location.

- [ ] **Step 3: Manual verification note (no automated test for this task)**

Per the approved design's Testing section, verify via a dogfooding run with a large candidate
bucket (e.g. `xss` on a repo with many similar sinks) that per-finding attribution stays
correct — this is a follow-up action for whoever next runs a full audit with this harness, not
a blocking step of this plan.

- [ ] **Step 4: Commit**

```bash
git add skills/sec-harness/agents/investigate.md
git status
git commit -m "docs(investigate): add cross-candidate attribution self-check"
```

---

## Self-Review

**Spec coverage** (checked against `2026-08-04-aghast-openant-adoption-design.md`):
- Section A (custom check bundles) → Tasks 7-8. Bundle shape, in-repo location, discovery,
  execution via existing `investigate.md`, full gate-ladder rigor, unrouted-class accounting
  (`merge_custom_check_classes` feeds the same `agents_to_spawn` list `unrouted_candidate_classes`
  already checks) — all covered.
- Section B (schema hardening) → Tasks 1-4. `finding.schema.json`, `schema.py` validator,
  `findings_gate.py` wiring, additive to existing semantic checks — all covered. The design's
  optional "same treatment for `kb/discovery-ledger.json`/`kb/gates/*.json`" was investigated:
  both already have hand-rolled validators (`discovery_ledger.validate_discovery_ledger`,
  `phase_gate` checks) and no schema file precedent for either — out of scope for this plan
  since the design only conditions this on "if inspection during implementation shows they
  currently lack schemas," and adding two more schema files for ledgers with working hand-rolled
  validators is separate scope, not requested.
- Section C (anti-hallucination guard) → Task 9. Prompt-only, scoped to `investigate.md`, scope
  decision documented — covered.
- Section D (entry-point detection) → Tasks 5-6. Regex tables per language, `is_entry_point`/
  `entry_point_reason` unconditional on Tier-1 build, `entry_point_nodes` query helper —
  covered. The design's "consumers" bullet (`no_path`/`attacker_controls` gaining a seed set,
  `phase-adversary.md`/`threat-model` cross-checking the LLM's attack surface) is a downstream
  *usage* of this data, not a structural requirement of Tier-1 build itself — the data
  (`entry_point_nodes`) is now available for that follow-on wiring, which was not called out as
  its own task in the design's four numbered sections.

**Placeholder scan:** no `TBD`/`TODO`/"implement later" strings in any task; every code block is
complete, runnable code; Task 3's first draft placeholder code block was replaced inline with
the real test before being finalized (visible in the task itself as the corrected version).

**Type/signature consistency:** `CustomCheck` fields match across Task 7's dataclass definition
and all of its test usages (`check.check_id`, `check.severity`, `check.instructions_path`,
`check.semgrep_rule_path`). `classify_entry_point(lang, all_lines, start, end)` signature is
identical between Task 5's definition and Task 6's call site. `validate(data, schema)` signature
is identical between Task 1's definition and every call site in Tasks 2-4.
