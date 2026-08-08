from __future__ import annotations

import hashlib
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


def test_cli_writes_combined_artifacts_and_sarif(tmp_path: Path, capsys):
    """Test CLI writes combined artifacts, SARIF, and immutably preserves member sidecars."""
    ma = build_member(
        tmp_path,
        slug="svc-1",
        scan_scope=".",
        findings=[
            {
                "id": "C-1",
                "cls": "authz",
                "status": "confirmed",
                "severity": "high",
                "rule_id": "no-mr",
                "file": "api.go",
                "line": 5,
                "message": "handler has no MR",
                "evidence_sources": ["ast-grep:x"],
            }
        ],
    )
    mb = {
        **build_member(
            tmp_path,
            slug="svc-2",
            scan_scope=".",
            findings=[
                {
                    "id": "C-2",
                    "cls": "authz",
                    "status": "needs-deployment-testing",
                    "severity": "medium",
                    "rule_id": "unscoped-check",
                    "file": "rbac.js",
                    "line": 12,
                    "message": "check is unscoped",
                    "evidence_sources": ["ast-grep:y"],
                }
            ],
        ),
        "role": "service-enforcer",
    }
    manifest = tmp_path / "product.json"
    manifest.write_text(json.dumps({"product": "test", "members": [ma, mb]}))
    out = tmp_path / "corr"

    # Capture member sidecar before main() for immutability check
    findings_files = list(tmp_path.glob("**/.sec-harness/**/findings/*.json"))
    assert len(findings_files) > 0, "No findings files found in member sidecars"
    sidecar_file = findings_files[0]
    sha_before = hashlib.sha256(sidecar_file.read_bytes()).hexdigest()

    rc = main(["--manifest", str(manifest), "--out", str(out)])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["artifacts"] == 4

    # Verify artifact files exist
    art = out / "artifacts"
    for name in ("ARCHITECTURE.md", "THREAT_MODEL.md", "REDTEAM.md", "FINDINGS.md"):
        assert (art / name).is_file(), f"Missing {name}"

    # Verify SARIF structure
    sarif = json.loads((art / "report.sarif").read_text())
    assert sarif["runs"][-1]["tool"]["driver"]["name"] == "sec-harness-correlation"

    # Verify immutability of member sidecars
    sha_after = hashlib.sha256(sidecar_file.read_bytes()).hexdigest()
    assert sha_before == sha_after, "Member sidecar was modified during correlation"
