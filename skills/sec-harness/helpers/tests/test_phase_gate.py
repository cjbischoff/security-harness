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


def test_ref_resolves_line_range(tmp_path):
    # Regression: "path:43-53" range citations must anchor on the start line rather than
    # falling through to a path-existence check with the literal ":43-53" suffix glued on
    # (harness "range-ref bug").
    root = _repo(tmp_path)
    assert ref_resolves(root, "internal/auth/gate.go:1-2")       # start line in range
    assert not ref_resolves(root, "internal/auth/gate.go:50-60")  # start line out of range


def test_resolve_ref_basename_fallback(tmp_path):
    # Regression: an agent citing a package-relative or bare-basename path (harness defect 5)
    # should still resolve via a unique basename match under root, with a note recording the
    # fallback so the correction stays visible rather than silent.
    from sec_harness.phase_gate import resolve_ref
    root = _repo(tmp_path)
    resolved, note = resolve_ref(root, "gate.go:2")  # bare basename, missing internal/auth/ prefix
    assert resolved is True
    assert note is not None and "basename search" in note
    assert not ref_resolves(root, "gate.go:99")  # fallback still enforces line range


def test_resolve_ref_ambiguous_basename_unresolved(tmp_path):
    from sec_harness.phase_gate import resolve_ref
    root = _repo(tmp_path)
    (root / "other").mkdir()
    (root / "other" / "gate.go").write_text("package other\n")
    resolved, note = resolve_ref(root, "gate.go")
    assert resolved is False
    assert note is not None and "ambiguous" in note


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
    assert rec["warning"] is None


def test_build_gate_record_warns_on_total_rejection():
    # Regression: every claim rejected deterministically must not read as a clean pass —
    # nothing ever reached the adversary (the silent-total-bypass half of harness defect 5).
    decisions = [
        GateDecision("a", "reject", ["ref does not resolve"]),
        GateDecision("b", "reject", ["ref does not resolve"]),
    ]
    rec = build_gate_record("threat-model", decisions)
    assert rec["sent_to_adversary"] == []
    assert rec["warning"] is not None and "gate failure" in rec["warning"]


def test_build_gate_record_no_warning_when_no_claims():
    rec = build_gate_record("recon", [])
    assert rec["warning"] is None


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


def test_claims_from_profile_extracts_attack_surface_claims():
    from types import SimpleNamespace

    from sec_harness.phase_gate import claims_from_profile
    p = SimpleNamespace(entrypoints=[], subsystems=[], attack_surface=["sqli"],
                        agents_to_spawn=["sqli"],
                        attack_surface_evidence={"sqli": ["src/db.py:10"]})
    claims = claims_from_profile(p)
    surf = next(c for c in claims if c["id"] == "surf-sqli")
    assert surf["refs"] == ["src/db.py:10"] and "sqli" in surf["text"]


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


def test_extracts_terraform_range_citation():
    from sec_harness.phase_gate import claims_from_markdown
    claims = claims_from_markdown("The role at `infra/azure/main.tf:150-159` is over-scoped.")
    refs = [r for c in claims for r in c["refs"]]
    assert "infra/azure/main.tf:150" in refs  # range anchors on start line


def test_extracts_yaml_citation():
    from sec_harness.phase_gate import claims_from_markdown
    claims = claims_from_markdown("DB_SSLMODE=disable at charts/x/responder.yaml:132")
    refs = [r for c in claims for r in c["refs"]]
    assert "charts/x/responder.yaml:132" in refs


def test_still_extracts_go_citation():
    from sec_harness.phase_gate import claims_from_markdown
    claims = claims_from_markdown("`internal/svc/events.go:39` reads Envelope.Source")
    refs = [r for c in claims for r in c["refs"]]
    assert "internal/svc/events.go:39" in refs
