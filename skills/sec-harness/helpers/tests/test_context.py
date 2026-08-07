"""Tests for context ingestion (C1) + driving helpers."""
from __future__ import annotations

from pathlib import Path

from sec_harness.context import (
    Context,
    ContextItem,
    control_findings,
    control_worklist,
    discover_context_files,
    hunt_rows,
    load,
    manual_review_findings,
    render_markdown,
    save,
)
from sec_harness.models import FindingStatus
from sec_harness.workspace import Workspace


def test_finds_monorepo_root_service_docs_from_subdir(tmp_path: Path):
    repo = tmp_path / "mono"
    (repo / "internal" / "svc").mkdir(parents=True)
    (repo / "internal" / "svc" / "README.md").write_text("svc readme")
    svc_docs = repo / "docs" / "services" / "svc"
    svc_docs.mkdir(parents=True)
    (svc_docs / "data-flow.md").write_text("# data flow")
    # _SKIP must apply to both new scan_scope sub-tree and canonical service-doc dirs
    (repo / "internal" / "svc" / "node_modules").mkdir(parents=True)
    (repo / "internal" / "svc" / "node_modules" / "evil.md").write_text("no")
    (svc_docs / "dist").mkdir()
    (svc_docs / "dist" / "skip.md").write_text("no")
    found = discover_context_files(repo, "internal/svc")
    assert "internal/svc/README.md" in found
    assert "docs/services/svc/data-flow.md" in found  # was MISSED before
    assert not any("node_modules" in f for f in found)
    assert not any("dist" in f for f in found)


def test_ingests_puml_text_diagrams(tmp_path: Path):
    repo = tmp_path / "repo"
    d = repo / "docs" / "service-story" / "DataFlowDiagrams"
    d.mkdir(parents=True)
    (d / "flow.puml").write_text("@startuml\n@enduml")
    (d / "flow.puml.png").write_bytes(b"\x89PNG")
    found = discover_context_files(repo)
    assert "docs/service-story/DataFlowDiagrams/flow.puml" in found


def test_backcompat_single_arg_whole_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "a.md").write_text("x")
    found = discover_context_files(repo)
    assert "docs/a.md" in found


def _ctx():
    return Context(items=[
        ContextItem(kind="trust_boundary", text="public ingress requires Azure AD token",
                    where="internal/gateway/handler.go", source_doc="openspec/specs/ingress-auth-hardening/spec.md"),
        ContextItem(kind="claimed_control", cls="authz", text="reject JQL outside project allowlist",
                    where="internal/auth", verify_hint="grep for the recognizer; confirm reject path",
                    source_doc="openspec/changes/jira-agent-jql-safelist/design.md"),
        ContextItem(kind="prior_finding", trust="prior-scan", cls="crypto",
                    text="confirmed crypto: mcrypt no-MAC [fp:abcd]", where="library/DW/Crypter.php:34"),
    ])


def test_validate_and_kinds():
    c = _ctx()
    assert c.validate() == []
    assert len(c.of_kind("claimed_control")) == 1
    bad = Context(items=[ContextItem(kind="nope", text="")])
    assert bad.validate()


def test_discover_finds_docs(tmp_path):
    (tmp_path / "docs").mkdir(); (tmp_path / "docs" / "a.md").write_text("x")
    (tmp_path / "openspec" / "specs").mkdir(parents=True)
    (tmp_path / "openspec" / "specs" / "s.md").write_text("y")
    (tmp_path / "SECURITY.md").write_text("z")
    (tmp_path / "node_modules").mkdir(); (tmp_path / "node_modules" / "junk.md").write_text("no")
    found = discover_context_files(tmp_path)
    assert "docs/a.md" in found and "openspec/specs/s.md" in found and "SECURITY.md" in found
    assert not any("node_modules" in f for f in found)


def test_hunt_rows_and_control_worklist():
    c = _ctx()
    rows = hunt_rows(c)
    assert any("trust boundary" in r["why"] for r in rows)
    assert any("verify claimed control" in r["why"] for r in rows)
    wl = control_worklist(c)
    assert len(wl) == 1 and wl[0]["cls"] == "authz" and wl[0]["verify_hint"]


def test_save_load_render(tmp_path):
    ws = Workspace(tmp_path); ws.ensure()
    save(ws, _ctx())
    assert (ws.kb / "context.json").exists() and (ws.kb / "CONTEXT.md").exists()
    md = render_markdown(_ctx())
    assert "claims to verify" in md.lower() and "reject JQL" in md
    assert load(ws).of_kind("claimed_control")[0].cls == "authz"


def test_control_findings_only_for_unenforced():
    c = Context(items=[
        ContextItem(kind="claimed_control", cls="authz", text="reject JQL outside allowlist",
                    where="internal/auth/jql.go:42", verify_status="MISSING",
                    source_doc="design.md"),
        ContextItem(kind="claimed_control", cls="ssrf", text="egress allowlist",
                    where="internal/net", verify_status="BYPASSABLE"),
        ContextItem(kind="claimed_control", cls="authz", text="401 on public",
                    where="internal/gw.go:5", verify_status="PRESENT"),  # enforced -> no finding
        ContextItem(kind="claimed_control", cls="authz", text="unverified", where="x.go"),  # "" -> none
    ])
    findings = control_findings(c, discovery_sha="abc")
    assert len(findings) == 2
    assert {f.id for f in findings} == {"CTL-0001", "CTL-0002"}
    for f in findings:
        assert f.status is FindingStatus.CANDIDATE
        # trust contract: a doc claim alone can never confirm — llm-claimed evidence only.
        assert f.evidence_sources == ["llm-claimed:doc-claim"]
        assert f.discovery_sha == "abc"
    assert findings[0].file == "internal/auth/jql.go" and findings[0].line == 42


def test_verify_status_validation():
    bad = Context(items=[ContextItem(kind="claimed_control", text="x", verify_status="NOPE")])
    assert any("verify_status" in e for e in bad.validate())


def test_manual_review_findings_from_attack_leads():
    c = Context(items=[
        ContextItem(kind="attack_lead", cls="ssrf", text="CI deploy-token reachable via webhook",
                    where="internal/ci/deploy.go:88", source_doc="docs/ci.md"),
    ])
    findings = manual_review_findings(c, discovery_sha="abc")
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "LEAD-0001"
    assert f.status is FindingStatus.NEEDS_DEPLOYMENT_TESTING
    assert f.cls == "manual-review"
    assert f.evidence_sources == ["llm-claimed:doc-lead"]
    assert f.file == "internal/ci/deploy.go" and f.line == 88
    assert f.discovery_sha == "abc"
