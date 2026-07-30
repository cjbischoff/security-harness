"""Tests for the osv-scanner SCA wrapper."""

import json

import pytest

from sec_harness.sca import ScaError, parse_osv_json, run_sca

_OSV = {
    "results": [{
        "source": {"path": "/t/package-lock.json"},
        "packages": [{
            "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
            "vulnerabilities": [
                {"id": "GHSA-xxxx", "summary": "Prototype pollution",
                 "database_specific": {"severity": "HIGH"}},
            ],
        }],
    }]
}


def test_parse_osv_json():
    fs = parse_osv_json(_OSV)
    assert len(fs) == 1
    f = fs[0]
    assert f.cls == "deps"
    assert "lodash@4.17.15" in f.message and "GHSA-xxxx" in f.message
    assert f.evidence_sources == ["sca:osv:GHSA-xxxx"]
    assert f.severity.value == "high"


def test_run_sca_absent_raises():
    with pytest.raises(ScaError, match="not installed"):
        run_sca("/t", has_tool=lambda n: None)


def test_run_sca_parses(monkeypatch):
    class R:
        stdout = json.dumps(_OSV); stderr = ""; returncode = 1  # exit 1 = vulns found
    fs = run_sca("/t", runner=lambda *a, **k: R(), has_tool=lambda n: "/x")
    assert len(fs) == 1 and fs[0].cls == "deps"


def test_run_sca_empty_output_errors():
    class R:
        stdout = "  "; stderr = "boom"; returncode = 127
    with pytest.raises(ScaError, match="no output"):
        run_sca("/t", runner=lambda *a, **k: R(), has_tool=lambda n: "/x")


def test_sca_source_is_tool_receipt():
    from sec_harness.evidence import is_tool_receipt
    assert is_tool_receipt("sca:osv:GHSA-xxxx") is True


def test_run_sca_no_package_sources_is_empty_not_error():
    class R:
        stdout = ""; stderr = "No package sources found, --help for usage information."; returncode = 128
    assert run_sca("/t", runner=lambda *a, **k: R(), has_tool=lambda n: "/x") == []
