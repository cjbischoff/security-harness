# Testing Patterns

**Analysis Date:** 2026-07-30

**Scope:** `skills/sec-harness/helpers/` only. The Python reference test suite and dev-only eval harness that the Go port must reproduce (or replace with equivalent coverage).

## Test Framework

**Runner:**
- `pytest` (dev dependency `pytest>=8`), config in `skills/sec-harness/helpers/pyproject.toml`:
  ```toml
  [tool.pytest.ini_options]
  testpaths = ["tests"]
  ```
- ~282 test functions across 51 `test_*.py` files under `helpers/tests/`.

**Assertion Library:**
- Plain `assert` (pytest rewriting). No unittest, no external assertion libs — stdlib only.

**Run Commands (from `skills/sec-harness/helpers/`):**
```bash
uv run pytest                       # run the whole suite
uv run pytest tests/test_prefilter.py   # single module
uv run pytest -k prefilter          # by keyword
uv run ruff check                   # lint (line-length 100, py312)
uv run ruff format                  # format
uv run ty check                     # type-check
```
All dev tooling is driven through `uv run` against the `[dependency-groups] dev` group (`pytest`, `ruff`, `ty`). The core package itself has zero runtime dependencies.

## Test File Organization

**Location:**
- Separate `tests/` directory (not co-located), mirroring module names one-to-one: `sec_harness/prefilter.py` → `tests/test_prefilter.py`, `evidence.py` → `test_evidence.py`, etc.
- Cross-cutting suites don't map to a single module: `test_contracts.py` (Layer C prompt↔schema), `test_wiring.py` (backend reachability), `test_cli_e2e.py`, `test_bench.py`.

**Naming:**
- Files: `test_<module>.py`. Functions: `test_<behavior_described>` — long descriptive names (`test_prefilter_records_codeql_failure_without_crashing`, `test_investigate_example_passes_the_gate`).

**Fixtures directory:**
- `helpers/tests/conftest.py` — shared fixtures. Currently one: `fixture_repo` returns the path to `fixtures/vulnerable_repo` (`conftest.py:8`).
- `helpers/tests/fixtures/` and `helpers/tests/fixtures_struct/` — test-local fixture data.

## Test Structure

**Suite organization:**
- Flat module-level test functions (no classes). Sections delimited by comment banners:
  ```python
  # ---- corpus ----
  # ---- judge ----
  ```
  See `tests/test_bench.py:26`.

**Per-test setup:**
- `tmp_path` (pytest builtin) for filesystem isolation. Workspaces are created inline:
  ```python
  ws = Workspace(tmp_path / "ws"); ws.ensure()
  ```
  (the `;` one-liner is why `E702` is ignored for `tests/**`).

**Local builder helpers:**
- Each test module defines tiny private constructors to keep tests terse:
  ```python
  def _cand(cls, file, line):
      return Finding(id="X", rule_id="r", cls=cls, status=FindingStatus.CANDIDATE,
                     severity=Severity.HIGH, file=file, line=line, message="m")
  ```
  (`tests/test_prefilter.py:9`; also `_profile()`, `_entry()`, `_f()` in `test_bench.py`).

## Mocking

**No mocking framework** — the injectable-runner convention replaces it. Every side-effecting function accepts its dependency as a keyword-only injectable (see CONVENTIONS.md), so tests pass lambdas/stubs directly.

**Patterns:**
```python
# stub a backend runner
sem = lambda target, config, **k: [_cand("sqli", "a.go", 1)]

# stub binary presence
has_tool=lambda n: None if n == "codeql" else "/x"

# assert a path is NOT taken by injecting a throwing stub
cql = lambda *a, **k: (_ for _ in ()).throw(AssertionError("codeql should not run"))

res = run_prefilter(ws, "tgt", _profile(), semgrep=sem, codeql=cql, has_tool=has_tool)
```
(`tests/test_prefilter.py:26-46`)

**What to inject:** subprocess runners, `shutil.which`, trust/qlpack checkers, exclusion loaders — anything touching the environment.
**What NOT to mock:** the `Finding`/`Workspace` models and pure parsers — exercise them for real against `tmp_path`.

## Fixtures and Test Data

**The intentional synthetic vulnerable repo:**
- `helpers/fixtures/vulnerable_repo/` — a deliberately vulnerable Flask app used as a detection target. `app.py` seeds a hardcoded secret (`API_KEY = "sk_live_..."`) and a `'%s' % uid` SQL injection, each tagged `# (seeded vuln)`. Module docstring: *"Intentionally vulnerable fixture app for sec-harness tests. Do not deploy."* This is expected — do not "fix" it.

**Golden fixtures (`helpers/fixtures/`):**
- `golden_raw_finding.json`, `golden_scan_profile.json`, `golden_sqli_patch.diff` — canonical artifacts validated against the live models (`tests/test_contracts.py:65`, skipped gracefully if absent).

## Bench — dev-only eval harness (`helpers/bench/`)

Not shipped with the skill; measures and locks detection quality. Three layers (`helpers/bench/README.md`):

- **Layer A — detection benchmark.** Labelled corpus (positives to find, negatives to stay silent on) → clone@commit or scan a local checkout → scan via a swappable adapter → judge → precision/recall segmented by source & class.
- **Layer B — regression corpus.** Corpus entries carry a `lifecycle`; a `locked` positive that stops being detected is a hard failure (`scorecard.regressed`, exit 1). Grow it every time the harness confirms/rejects a real finding.
- **Layer C — contract/wiring tests.** Live in the main suite, not bench: `tests/test_contracts.py` (prompt↔schema drift) and `tests/test_wiring.py` (backend reachability). Deterministic, no LLM.

**Bench modules:**
- `corpus.py` — `CorpusEntry`/`Corpus`, `load_corpus(dir)`.
- `judge.py` — `deterministic_match` (class + file + line-proximity + fingerprint; CVE for deps) then an optional injected `llm_judge` for fuzzy credit.
- `tally.py` — precision/recall by source & class, FP-rate, regressions; `Scorecard.to_markdown()`/`to_dict()`. Synthetic recall is never blended into the headline number (real-confirmed only).
- `adapter.py` — `ScanAdapter` protocol; `BinaryAdapter` (drives a scanner binary — the Go migration seam), `WorkspaceAdapter` (grades an already-scanned workspace), `CCSkillAdapter` (native SDK driver seam).
- `run.py` — orchestrates clone/scan/judge/tally; resumable via a findings cache.

**Run bench:**
```bash
python -m bench.run --corpus bench/corpus_seed --run-dir /tmp/bench --workspaces <dir>
python -m bench.run --corpus bench/corpus_seed --run-dir /tmp/bench --binary "sec-harness-go scan"
```

**`corpus_seed/*.json` are gitignored.** Rule: `.gitignore:32` → `skills/sec-harness/helpers/bench/corpus_seed/*.json`. They are built from this project's real session findings (confirmed = locked positives, correctly-rejected leads = negatives) and are not committed. `corpus_seed/README.md` is tracked; the data JSONs are not. The Go port must regenerate/seed its own corpus.

## Test Types

**Unit tests:** the bulk — pure parsers, gates, models, scoring, dedupe, evidence grading. Injected stubs for anything external.

**Contract tests (Layer C):** `tests/test_contracts.py` greps ` ```json ` blocks out of the agent prompt `.md` files under `agents/`, strips `<placeholder>` tokens, and validates each against the real `Finding` model + `validate_findings` gate — catches producer↔schema drift without running an LLM (`test_contracts.py:1-62`).

**Wiring tests:** `tests/test_wiring.py` — backend reachability / pipeline composition.

**E2E:** `tests/test_cli_e2e.py` drives the `argparse` CLI end-to-end.

## Common Patterns

**Assert-the-negative-path (verify something did NOT run):**
```python
cql = lambda *a, **k: (_ for _ in ()).throw(AssertionError("codeql should not run"))
```

**Error-list gate assertions:**
```python
assert validate_findings(ws) == []          # gate-clean
assert any("V3" in e for e in c.validate())  # specific error surfaced
```
(`tests/test_contracts.py:62`, `tests/test_bench.py:31`)

**Failure recorded, not swallowed:**
```python
res = run_prefilter(..., codeql=boom, ...)   # boom raises CodeQLError
assert res["backends_run"] == ["semgrep"]    # codeql not counted as run
assert res["failed"][0]["backend"] == "codeql"
assert res["candidates"] == 1                # other backends still persisted
```
(`tests/test_prefilter.py:49-65`)

---

*Testing analysis: 2026-07-30*
