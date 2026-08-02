"""Tests for the reusable phase adversary gate (deterministic half)."""

from sec_harness.phase_gate import (
    GateDecision,
    build_gate_record,
    ref_resolves,
    run_phase_checks,
    write_gate_record,
)
from sec_harness.workspace import Workspace


def _repo(tmp_path):
    (tmp_path / "internal" / "auth").mkdir(parents=True)
    (tmp_path / "internal" / "auth" / "gate.go").write_text("package auth\nfunc Check() {}\n")
    return tmp_path


def test_ref_resolves(tmp_path):
    root = _repo(tmp_path)
    assert ref_resolves(root, "internal/auth/gate.go")       # file exists
    assert ref_resolves(root, "internal/auth")               # dir exists
    assert ref_resolves(root, "internal/auth/gate.go:2")     # line in range
    assert not ref_resolves(root, "internal/auth/gate.go:99")  # out of range
    assert not ref_resolves(root, "nope/missing.go")         # missing
    assert not ref_resolves(root, "")                        # empty


def test_run_phase_checks(tmp_path):
    root = _repo(tmp_path)
    claims = [
        {"id": "boundary", "refs": ["internal/auth/gate.go:1"]},   # resolves
        {"id": "bad", "refs": ["internal/auth/gate.go:999"]},      # does not resolve
        {"id": "norefs", "refs": []},                              # judgment-only
    ]
    d = {g.claim_id: g for g in run_phase_checks(claims, str(root))}
    assert d["boundary"].status == "to-adversary"
    assert d["bad"].status == "reject"
    assert d["norefs"].status == "to-adversary" and d["norefs"].reasons


def test_build_gate_record_survivors():
    decisions = [
        GateDecision("a", "to-adversary"),
        GateDecision("b", "to-adversary"),
        GateDecision("c", "reject", ["ref does not resolve"]),
    ]
    rec = build_gate_record("recon", decisions, verdicts={"a": "CONFIRMED", "b": "INVALIDATED"})
    assert rec["phase"] == "recon"
    assert rec["rejected_deterministically"] == ["c"]
    assert rec["survivors"] == ["a"]  # b invalidated by the adversary


def test_write_gate_record(tmp_path):
    ws = Workspace(tmp_path)
    ws.ensure()
    rec = build_gate_record("threat-model", [GateDecision("x", "to-adversary")])
    p = write_gate_record(ws, "threat-model", rec)
    assert p.exists() and p.name == "threat-model.json"


def test_gate_decision_and_record_carry_claim_content(tmp_path):
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
