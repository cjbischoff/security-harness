from __future__ import annotations

import json
from pathlib import Path

from sec_harness.correlate.cli import main
from tests.correlate_fixtures import build_member


def test_cli_writes_edges(tmp_path: Path):
    ma = build_member(tmp_path, slug="a-1", scan_scope=".",
                      findings=[{"id": "C-1", "cls": "deps", "status": "confirmed", "severity": "low",
                                 "rule_id": "osv:GHSA-x", "file": "lock", "line": 1, "message": "m",
                                 "evidence_sources": ["sca:osv:GHSA-x"]}])
    mb = build_member(tmp_path, slug="b-1", scan_scope=".",
                      findings=[{"id": "C-2", "cls": "deps", "status": "confirmed", "severity": "high",
                                 "rule_id": "osv:GHSA-x", "file": "lock", "line": 1, "message": "m",
                                 "evidence_sources": ["sca:osv:GHSA-x"]}])
    manifest = tmp_path / "product.json"
    manifest.write_text(json.dumps({"product": "p", "members": [ma, mb]}))
    out = tmp_path / "corr"
    rc = main(["--manifest", str(manifest), "--out", str(out)])
    assert rc == 0
    edges = json.loads((out / "edges.json").read_text())
    assert any(e["type"] == "shared-dependency" and e["key"] == "GHSA-x" for e in edges)
    assert (out / "product.json").exists()  # manifest copied into the workspace


def test_cli_writes_verdicts(tmp_path: Path):
    ma = build_member(tmp_path, slug="rbac-1", scan_scope=".", findings=[
        {"id": "A-1", "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
         "rule_id": "context:claimed-control", "file": "src/rbac/spec.js", "line": 1,
         "message": "privilege 'p write' unscoped; enforcement out-of-repo",
         "evidence_sources": ["ast-grep:x"]}])
    mb = {**build_member(tmp_path, slug="svc-1", scan_scope=".", findings=[
        {"id": "E-1", "cls": "authz", "status": "needs-deployment-testing", "severity": "medium",
         "rule_id": "no-mr", "file": "api.go", "line": 9,
         "message": "handler for 'p write' has no MR check", "evidence_sources": ["ast-grep:y"]}]),
          "role": "service-enforcer"}
    manifest = tmp_path / "product.json"
    manifest.write_text(json.dumps({"product": "p", "members": [ma, mb]}))
    out = tmp_path / "corr"
    rc = main(["--manifest", str(manifest), "--out", str(out)])
    assert rc == 0
    verdicts = json.loads((out / "verdicts.json").read_text())
    v = next(v for v in verdicts if v["finding_ref"].startswith("rbac-1#."))
    assert v["direction"] == "promote" and v["correlated_status"] == "confirmed"
