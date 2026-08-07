"""Tests for deterministic dedupe."""

from pathlib import Path

from sec_harness import graph as g
from sec_harness.dedupe import dedupe_findings
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, read_findings, write_findings

FIXTURE = Path(__file__).parent / "fixtures" / "graph_target"


def _f(id_, cls, file, line, sev, status=FindingStatus.RAW):
    return Finding(id=id_, rule_id="r", cls=cls, status=status, severity=sev,
                   file=file, line=line, message="m")


def test_dedupe_marks_lower_severity_as_duplicate(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [
        _f("F-0002", "sqli", "app.py", 18, Severity.MEDIUM),
        _f("A-0001", "sqli", "app.py", 18, Severity.HIGH),
    ])
    n = dedupe_findings(ws)
    assert n == 1
    by_id = {f.id: f for f in read_findings(ws)}
    assert by_id["A-0001"].status is FindingStatus.RAW          # primary (higher sev)
    assert by_id["F-0002"].status is FindingStatus.DUPLICATE
    assert by_id["F-0002"].duplicate_of == "A-0001"


def test_dedupe_leaves_distinct_findings(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [
        _f("F-0001", "secrets", "app.py", 9, Severity.HIGH),
        _f("F-0002", "sqli", "app.py", 18, Severity.HIGH),
    ])
    assert dedupe_findings(ws) == 0


def test_dedupe_preserves_distinct_findings_at_same_site(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    a = Finding(id="F-1", rule_id="r", cls="ssrf", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=18, message="m",
                dataflow=["req.body.url", "isPrivateIp", "fetch"])
    b = Finding(id="F-2", rule_id="r", cls="ssrf", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=18, message="m",
                dataflow=["req.query.target", "isPrivateIp", "axios.get"])
    write_findings(ws, [a, b])
    assert dedupe_findings(ws) == 0
    statuses = {f.id: f.status for f in read_findings(ws)}
    assert statuses["F-1"] is FindingStatus.RAW and statuses["F-2"] is FindingStatus.RAW


def test_dedupe_merges_same_fact_across_classes(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    a = Finding(id="F-1", rule_id="r", cls="ssrf", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=18, message="m",
                dataflow=["req.body.url", "fetch"])
    b = Finding(id="F-2", rule_id="r", cls="authz", status=FindingStatus.RAW,
                severity=Severity.HIGH, file="app.py", line=18, message="m",
                dataflow=["req.body.url", "fetch"])
    write_findings(ws, [a, b])
    assert dedupe_findings(ws) == 1
    statuses = {f.id: f.status for f in read_findings(ws)}
    assert FindingStatus.DUPLICATE in statuses.values()


def test_dedupe_ignores_non_active_statuses(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [
        _f("F-0002", "sqli", "app.py", 18, Severity.HIGH),
        _f("F-0003", "sqli", "app.py", 18, Severity.LOW, status=FindingStatus.REJECTED),
    ])
    assert dedupe_findings(ws) == 0  # rejected one not considered


def test_dedupe_stamps_fingerprint(tmp_path):
    """Test that dedupe stamps a stable fingerprint on every active finding."""
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [
        _f("F-0001", "sqli", "a.py", 1, Severity.HIGH),
    ])
    dedupe_findings(ws)
    f = read_findings(ws)[0]
    assert f.fingerprint is not None and len(f.fingerprint) == 12


def test_dedupe_honors_preset_duplicate_of(tmp_path):
    # sibling sinks in one function, different lines -> exact (file,line,cls)
    # collision won't catch them, but the investigator set duplicate_of.
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    prim = _f("C-0089", "crypto", "Crypter.php", 34, Severity.HIGH)
    dup = _f("C-0090", "crypto", "Crypter.php", 37, Severity.HIGH)
    dup.duplicate_of = "C-0089"
    write_findings(ws, [prim, dup])
    n = dedupe_findings(ws)
    assert n == 1
    by_id = {f.id: f for f in read_findings(ws)}
    assert by_id["C-0089"].status is FindingStatus.RAW
    assert by_id["C-0090"].status is FindingStatus.DUPLICATE


def test_dedupe_ignores_duplicate_of_pointing_nowhere(tmp_path):
    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    dup = _f("C-0090", "crypto", "Crypter.php", 37, Severity.HIGH)
    dup.duplicate_of = "C-9999"  # primary absent
    write_findings(ws, [dup])
    assert dedupe_findings(ws) == 0
    assert read_findings(ws)[0].status is FindingStatus.RAW


def _raw(fid, line):
    return Finding(id=fid, rule_id="r", cls="sqli", status=FindingStatus.RAW,
                   severity=Severity.HIGH, file="app/db.py", line=line, message="m")


def test_dedupe_stamps_symbol_anchored_fingerprint(tmp_path):
    ws = Workspace(root=tmp_path / "ws")
    ws.ensure()
    g.save_graph(ws, g.build_tier1(FIXTURE, sha="x"))   # graph present
    f1, f2 = _raw("F-1", 1), _raw("F-2", 3)             # same run_query symbol, diff lines
    write_findings(ws, [f1, f2])
    dedupe_findings(ws)
    got = {f.id: f.fingerprint for f in read_findings(ws)}
    assert got["F-1"] == got["F-2"]                     # anchored to run_query -> equal


def test_dedupe_findings_records_stage(tmp_path):
    from sec_harness.state import load_state

    ws = Workspace(tmp_path / "workspace"); ws.ensure()
    write_findings(ws, [_f("F-0001", "sqli", "app.py", 18, Severity.HIGH)])
    dedupe_findings(ws)
    assert "dedupe" in load_state(ws).stages
