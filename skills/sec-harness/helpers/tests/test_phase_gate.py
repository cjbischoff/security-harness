"""Tests for the reusable phase adversary gate (deterministic half)."""

from typing import ClassVar

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


def test_claims_from_profile_extracts_entrypoints_and_subsystems():
    from sec_harness.phase_gate import claims_from_profile

    class P:  # minimal stand-in matching ScanProfile's attributes used here
        entrypoints: ClassVar = ["src/app.py:handler", "src/api.py:route"]
        subsystems: ClassVar = [{"name": "auth", "paths": ["src/auth.py"], "why": "login"}]

    claims = claims_from_profile(P())
    ids = {c["id"] for c in claims}
    assert "ep-0" in ids and any(c["id"].startswith("sub-0") for c in claims)
    ep0 = next(c for c in claims if c["id"] == "ep-0")
    assert ep0["refs"] == ["src/app.py"]           # path before the ':symbol'
    sub = next(c for c in claims if c["id"].startswith("sub-0"))
    assert sub["refs"] == ["src/auth.py"]


def test_claims_from_context_extracts_items_with_locations():
    from sec_harness.context import Context, ContextItem
    from sec_harness.phase_gate import claims_from_context

    ctx = Context(items=[
        ContextItem(kind="trust_boundary", text="API gateway terminates TLS",
                    where="src/gateway.py:10"),
        ContextItem(kind="prior_finding", text="no code location"),
    ])
    claims = claims_from_context(ctx)
    assert len(claims) == 2
    c0 = claims[0]
    assert c0["id"] == "ctx-0"
    assert c0["refs"] == ["src/gateway.py:10"]
    assert "trust_boundary" in c0["text"] and "API gateway terminates TLS" in c0["text"]
    assert claims[1]["refs"] == []


def test_claims_from_markdown_extracts_only_file_line_citations():
    from sec_harness.phase_gate import claims_from_markdown
    md = ("The gateway validates tokens in server/api/x.py:12 before dispatch.\n"
          "Also see server/api/y.py:40 for the session check.\n"
          "See the README for background; ARCHITECTURE mentions this too.\n")
    claims = claims_from_markdown(md)
    assert len(claims) == 2
    assert {c["refs"][0] for c in claims} == {"server/api/x.py:12", "server/api/y.py:40"}
    assert all(c["id"].startswith("md-") for c in claims)


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
