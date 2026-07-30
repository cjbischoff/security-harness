"""Fail-closed gate orchestrator (F12).

One place to run all quality gates on a fix/finding result. A `GATE_ROUTING` table
maps gate name -> stateless callable `(result) -> (ok: bool, detail: str)`. A
`REQUIRED_GATES` set fails the whole run if a required gate emitted ZERO invocations
(routing drift can't vacuously pass), and a missing result hard-fails. Adding a gate is
one table row.
"""

from __future__ import annotations


def _gate_scope(result: dict) -> tuple[bool, str]:
    """Changed files must be a subset of declared files_modified ∪ test_file."""
    changed = set(result.get("changed_files", []))
    allowed = set(result.get("files_modified", []))
    tf = result.get("test_file")
    if tf:
        allowed.add(tf)
    extra = changed - allowed
    return (not extra, "" if not extra else f"out-of-scope edits: {sorted(extra)}")


def _gate_idempotency(result: dict) -> tuple[bool, str]:
    """A stable vulnfix marker must be present (16 hex)."""
    key = result.get("vulnfix_key", "")
    ok = isinstance(key, str) and len(key) == 16 and all(c in "0123456789abcdef" for c in key)
    return (ok, "" if ok else "missing/invalid vulnfix_key (16 hex)")


def _gate_committed_test_naming(result: dict) -> tuple[bool, str]:
    """No committed file may be a transient exploit/verify scaffold."""
    bad = [f for f in result.get("changed_files", [])
           if f.rsplit("/", 1)[-1].startswith(("verify_VULN", "exploit_VULN"))]
    return (not bad, "" if not bad else f"committed scaffold(s): {bad}")


def _gate_verification_table(result: dict) -> tuple[bool, str]:
    """Every 'yes' cell in the verification table must carry a file:line citation."""
    rows = result.get("verification_table", [])
    for r in rows:
        for k, v in r.items():
            if v == "yes" and not r.get(f"{k}_cite"):
                return (False, f"'{k}=yes' lacks a citation")
    return (True, "")


# name -> callable. Adding a gate = one row.
GATE_ROUTING = {
    "scope": _gate_scope,
    "idempotency": _gate_idempotency,
    "committed-test-naming": _gate_committed_test_naming,
    "verification-table": _gate_verification_table,
}

# Gates that MUST run (their inputs are always present for a fix result). If a required
# gate is somehow skipped, the run fails closed rather than vacuously passing.
REQUIRED_GATES = ("scope", "committed-test-naming")


def run_gates(result: dict | None) -> dict:
    """Run every routed gate fail-closed.

    Args:
        result: The fix/finding result dict, or None.

    Returns:
        ``{pass: bool, gates: {name: {ok, detail}}}``. ``pass`` is False if the result
        is missing, any gate fails, or a REQUIRED gate did not run.
    """
    if result is None:
        return {"pass": False, "gates": {}, "error": "missing result (hard fail)"}
    gates: dict[str, dict] = {}
    for name, fn in GATE_ROUTING.items():
        ok, detail = fn(result)
        gates[name] = {"ok": ok, "detail": detail}
    ran = set(gates)
    missing_required = [g for g in REQUIRED_GATES if g not in ran]
    all_ok = all(g["ok"] for g in gates.values()) and not missing_required
    out = {"pass": all_ok, "gates": gates}
    if missing_required:
        out["error"] = f"required gate(s) did not run: {missing_required}"
    return out
