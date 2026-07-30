"""Tests for F1 citation auto-attach."""
from sec_harness.asvs import AsvsCatalog, default_catalog_path
from sec_harness.citations import (
    CLASS_ASVS,
    CLASS_CODEGUARD,
    annotate_findings,
    attach,
    citations_for,
)
from sec_harness.codeguard import default_codeguard_dir, load_rules
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, read_findings, write_findings


def _f(cls, status=FindingStatus.CONFIRMED, **kw):
    d = dict(id="F1", rule_id="r", cls=cls, status=status, severity=Severity.HIGH,
             file="a.py", line=1, message="m")
    d.update(kw)
    return Finding(**d)


def test_citations_for_crypto():
    asvs, cg = citations_for("crypto")
    assert asvs == ["v5.0.0-6.2.1", "v5.0.0-6.2.3"]
    assert cg == ["codeguard-0-cryptography"]


def test_attach_only_when_empty():
    f = _f("sqli")
    assert attach(f) is True and f.asvs_ids and f.codeguard_ids
    # already set -> no clobber
    f2 = _f("sqli", asvs_ids=["v5.0.0-9.9.9"])
    assert attach(f2) is False and f2.asvs_ids == ["v5.0.0-9.9.9"]


def test_annotate_workspace_skips_non_active(tmp_path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f("crypto", status=FindingStatus.CONFIRMED),
                        _f("xss", status=FindingStatus.CANDIDATE, id="C2")])
    n = annotate_findings(ws)
    assert n == 1  # only the confirmed one
    by = {f.id: f for f in read_findings(ws)}
    assert by["F1"].codeguard_ids == ["codeguard-0-cryptography"]
    assert by["C2"].asvs_ids == []  # candidate untouched


def test_all_mapped_ids_exist_in_seed():
    # every referenced ASVS id resolves in the shipped catalog; every codeguard file exists
    cat = AsvsCatalog.load(default_catalog_path())
    for cls, ids in CLASS_ASVS.items():
        for rid in ids:
            assert cat.get(rid) is not None, f"{cls} -> missing ASVS {rid}"
    rules = load_rules(default_codeguard_dir())
    for cls, cid in CLASS_CODEGUARD.items():
        assert cid in rules, f"{cls} -> missing CodeGuard {cid}"


def test_calibrate_attaches_citations(tmp_path):
    from sec_harness.calibrate import calibrate_findings
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f("crypto", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N")])
    calibrate_findings(ws)
    f = read_findings(ws)[0]
    assert f.asvs_ids == ["v5.0.0-6.2.1", "v5.0.0-6.2.3"] and f.risk_score
