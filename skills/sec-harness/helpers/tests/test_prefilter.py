"""Tests for the profile-driven prefilter dispatch."""

from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.prefilter import run_prefilter
from sec_harness.profile import ScanProfile
from sec_harness.workspace import Workspace, read_findings


def _cand(cls, file, line):
    return Finding(id="X", rule_id="r", cls=cls, status=FindingStatus.CANDIDATE,
                   severity=Severity.HIGH, file=file, line=line, message="m")


def _profile():
    return ScanProfile(
        languages=["go"], frameworks=[], entrypoints=[], runnable=True,
        attack_surface=["sqli", "ssrf"],
        sast_plan={
            "semgrep": {"run": True, "rulesets": ["rules/semgrep/go"]},
            "codeql": {"run": True, "languages": ["go"]},
        },
        agents_to_spawn=["sqli", "ssrf"], budget_hint={},
    )


def test_prefilter_runs_enabled_backends_and_merges(tmp_path):
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    sem = lambda target, config, **k: [_cand("sqli", "a.go", 1)]
    cql = lambda target, language, db_dir, **k: [_cand("ssrf", "b.go", 2)]
    res = run_prefilter(ws, "tgt", _profile(), semgrep=sem, codeql=cql, has_tool=lambda n: "/x",
                        qlpack_fn=lambda lang: True)
    assert res["candidates"] == 2
    assert set(res["backends_run"]) == {"semgrep", "codeql"}
    classes = {f.cls for f in read_findings(ws)}
    assert classes == {"sqli", "ssrf"}


def test_prefilter_skips_absent_backend(tmp_path):
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    sem = lambda target, config, **k: [_cand("sqli", "a.go", 1)]
    cql = lambda *a, **k: (_ for _ in ()).throw(AssertionError("codeql should not run"))
    # codeql binary absent -> must be skipped, not called
    res = run_prefilter(ws, "tgt", _profile(), semgrep=sem, codeql=cql,
                        has_tool=lambda n: None if n == "codeql" else "/x")
    assert "codeql" in res["skipped"]
    assert res["backends_run"] == ["semgrep"]


def test_prefilter_records_codeql_failure_without_crashing(tmp_path):
    from sec_harness.codeql import CodeQLError

    ws = Workspace(tmp_path / "ws"); ws.ensure()
    sem = lambda target, config, **k: [_cand("sqli", "a.go", 1)]

    def boom(*a, **k):
        raise CodeQLError("codeql database create failed (exit 32): go build error")

    # codeql present but its build fails -> recorded in `failed`, not swallowed as clean
    res = run_prefilter(ws, "tgt", _profile(), semgrep=sem, codeql=boom, has_tool=lambda n: "/x",
                        qlpack_fn=lambda lang: True)
    assert res["backends_run"] == ["semgrep"]        # codeql errored -> not counted as run
    assert len(res["failed"]) == 1
    assert res["failed"][0]["backend"] == "codeql"
    assert "build error" in res["failed"][0]["error"]
    assert res["candidates"] == 1                      # semgrep result still persisted


def test_prefilter_skips_codeql_on_untrusted_config(tmp_path):
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    sem = lambda target, config, **k: [_cand("sqli", "a.go", 1)]
    cql = lambda *a, **k: (_ for _ in ()).throw(AssertionError("codeql must not run on untrusted config"))
    res = run_prefilter(ws, "tgt", _profile(), semgrep=sem, codeql=cql,
                        has_tool=lambda n: "/x", trust_fn=lambda t: (False, "custom extractor"))
    assert any(x["backend"] == "codeql" and "extractor" in x["error"] for x in res["failed"])
    assert "codeql" not in res["backends_run"]


def test_prefilter_applies_exclusions(tmp_path):
    from sec_harness.exclusions import Exclusions

    ws = Workspace(tmp_path / "ws")
    ws.ensure()
    sem = lambda target, config, **k: [
        _cand("sqli", "a.go", 1),
        _cand("log-injection", "b.go", 2),
    ]
    res = run_prefilter(
        ws,
        "tgt",
        _profile(),
        semgrep=sem,
        codeql=lambda *a, **k: [],
        has_tool=lambda n: "/x" if n == "semgrep" else None,
        exclusions_fn=lambda w: Exclusions(classes={"log-injection"}),
    )
    assert res["excluded"] == 1
    assert {f.cls for f in read_findings(ws)} == {"sqli"}


def _cand_with_evidence(i, cls, src="semgrep:r"):
    return Finding(id=f"C-{i:04d}", rule_id="r", cls=cls, status=FindingStatus.CANDIDATE,
                   severity=Severity.LOW, file=f"a{i}.js", line=i, message="m",
                   evidence="", evidence_sources=[src])


def test_security_only_drops_unknown_semgrep(tmp_path):
    from sec_harness.workspace import Workspace
    ws = Workspace(tmp_path); ws.ensure()
    fake = [_cand_with_evidence(1, "xss"), _cand_with_evidence(2, "unknown"), _cand_with_evidence(3, "unknown")]
    prof = ScanProfile(["javascript"], [], [], True, ["xss"],
        {"semgrep": {"run": True, "rulesets": ["x"], "security_only": True}}, ["xss"], {})
    res = run_prefilter(ws, "t", prof, semgrep=lambda *a, **k: fake,
                        has_tool=lambda n: True, exclusions_fn=lambda w: __import__(
                            "sec_harness.exclusions", fromlist=["Exclusions"]).Exclusions([], [], []))
    assert res["candidates"] == 1
    assert res["dropped_nonsecurity"] == 2


def test_security_only_false_keeps_unknown(tmp_path):
    from sec_harness.exclusions import Exclusions
    from sec_harness.workspace import Workspace
    ws = Workspace(tmp_path); ws.ensure()
    fake = [_cand_with_evidence(1, "xss"), _cand_with_evidence(2, "unknown")]
    prof = ScanProfile(["javascript"], [], [], True, ["xss"],
        {"semgrep": {"run": True, "rulesets": ["x"], "security_only": False}}, ["xss"], {})
    res = run_prefilter(ws, "t", prof, semgrep=lambda *a, **k: fake,
                        has_tool=lambda n: True, exclusions_fn=lambda w: Exclusions([], [], []))
    assert res["candidates"] == 2
    assert res["dropped_nonsecurity"] == 0


def test_semgrep_runs_without_explicit_run_key(tmp_path):
    from sec_harness.exclusions import Exclusions
    from sec_harness.workspace import Workspace
    ws = Workspace(tmp_path); ws.ensure()
    called = []
    prof = ScanProfile(["javascript"], [], [], True, ["xss"],
        {"semgrep": {"rulesets": ["x"]}}, ["xss"], {})   # NO run key
    res = run_prefilter(ws, "t", prof,
                        semgrep=lambda *a, **k: called.append(1) or [_cand("xss", "a.js", 1)],
                        has_tool=lambda n: True, exclusions_fn=lambda w: Exclusions([], [], []))
    assert "semgrep" in res["backends_run"]
    assert called


def test_disabled_and_absent_backends_recorded(tmp_path):
    from sec_harness.exclusions import Exclusions
    from sec_harness.workspace import Workspace
    ws = Workspace(tmp_path); ws.ensure()
    prof = ScanProfile(["javascript"], [], [], True, ["xss"],
        {"semgrep": {"run": False, "rulesets": ["x"]},
         "codeql": {"run": True, "languages": ["javascript"]}},
        ["xss"], {})
    res = run_prefilter(ws, "t", prof, semgrep=lambda *a, **k: [],
                        has_tool=lambda n: False,   # codeql binary absent
                        exclusions_fn=lambda w: Exclusions([], [], []))
    assert res["skipped_reasons"]["semgrep"] == "disabled"
    assert res["skipped_reasons"]["codeql"] == "absent"
    assert res["backends_run"] == []


def test_serial_and_concurrent_identical(tmp_path):
    from sec_harness.exclusions import Exclusions
    from sec_harness.workspace import Workspace, read_findings

    # two rulesets, each returns findings out of sorted order; distinct files
    # per ruleset so the merged sort order is well-defined.
    def fake_semgrep(target, cfg, **k):
        if cfg == "r1":
            return [_cand_with_evidence(2, "sqli"), _cand_with_evidence(1, "xss")]
        return [_cand_with_evidence(3, "ssrf")]

    prof = ScanProfile(["javascript"], [], [], True, ["xss", "sqli", "ssrf"],
        {"semgrep": {"run": True, "rulesets": ["r1", "r2"], "security_only": True}},
        ["xss"], {})

    def run(mw):
        ws = Workspace(tmp_path / f"w{mw}"); ws.ensure()
        run_prefilter(ws, "t", prof, semgrep=fake_semgrep, has_tool=lambda n: True,
                      exclusions_fn=lambda w: Exclusions([], [], []), max_workers=mw)
        return [(f.id, f.file, f.line, f.cls) for f in read_findings(ws)]

    serial = run(1)
    concurrent = run(4)
    assert serial == concurrent
    # ids are contiguous C-0001.. in sorted (file,line) order
    assert [i for i, *_ in serial] == [f"C-{n:04d}" for n in range(1, len(serial) + 1)]


def test_codeql_disabled_recorded(tmp_path):
    from sec_harness.exclusions import Exclusions
    from sec_harness.workspace import Workspace
    ws = Workspace(tmp_path); ws.ensure()
    prof = ScanProfile(["javascript"], [], [], True, ["xss"],
        {"semgrep": {"run": True, "rulesets": ["x"]},
         "codeql": {"run": False, "languages": ["javascript"]}},
        ["xss"], {})
    res = run_prefilter(ws, "t", prof, semgrep=lambda *a, **k: [],
                        has_tool=lambda n: True,
                        exclusions_fn=lambda w: Exclusions([], [], []))
    assert res["skipped_reasons"]["codeql"] == "disabled"


def test_prefilter_records_codeql_pack_missing(tmp_path):
    # codeql binary present + config trusted, but the language query pack is not
    # installed -> a clear, loud `failed` entry (not a cryptic analyze exit-2),
    # and the codeql unit is never built.
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    sem = lambda target, config, **k: [_cand("sqli", "a.go", 1)]
    cql = lambda *a, **k: (_ for _ in ()).throw(AssertionError("codeql must not run without pack"))
    res = run_prefilter(ws, "tgt", _profile(), semgrep=sem, codeql=cql,
                        has_tool=lambda n: "/x", qlpack_fn=lambda lang: False)
    assert res["backends_run"] == ["semgrep"]
    assert res["skipped_reasons"].get("codeql") == "pack-missing"
    assert any(x["backend"] == "codeql" and "pack download" in x["error"] for x in res["failed"])


def test_prefilter_runs_secrets_and_sca_never_silent(tmp_path):
    from sec_harness.exclusions import Exclusions
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    prof = ScanProfile(["python"], [], [], True, ["secrets"],
        {"semgrep": {"run": True, "rulesets": ["x"]},
         "secrets": {"run": True},
         "sca": {"run": True, "lockfiles": ["package-lock.json"]}},
        ["secrets"], {})
    fake_sec = [_cand("secrets", "config.py", 3)]
    res = run_prefilter(ws, "t", prof,
        semgrep=lambda *a, **k: [],
        has_tool=lambda n: True,
        secrets_fn=lambda target: fake_sec,
        sca_fn=lambda target, **k: (_ for _ in ()).throw(__import__("sec_harness.sca", fromlist=["ScaError"]).ScaError("osv-scanner not installed")),
        exclusions_fn=lambda w: Exclusions([], [], []))
    assert "secrets" in res["backends_run"]
    assert res["skipped_reasons"].get("sca") == "absent"   # NOT silent
    assert any(x["backend"] == "sca" for x in res["failed"])
    assert res["candidates"] == 1  # the secrets finding persisted


def test_prefilter_never_silent_unimplemented_backend(tmp_path):
    from sec_harness.exclusions import Exclusions
    ws = Workspace(tmp_path / "ws2"); ws.ensure()
    # secrets declared run:true but we inject a no-op that still 'runs'; sca declared
    # but disabled -> must be recorded, never absent from the report.
    prof = ScanProfile(["python"], [], [], True, ["secrets"],
        {"semgrep": {"run": True, "rulesets": ["x"]},
         "sca": {"run": False}},
        [], {})
    res = run_prefilter(ws, "t", prof, semgrep=lambda *a, **k: [],
        has_tool=lambda n: True, secrets_fn=lambda t: [],
        exclusions_fn=lambda w: Exclusions([], [], []))
    assert res["skipped_reasons"].get("sca") == "disabled"


def test_run_prefilter_result_has_coverage(tmp_path):
    import json

    ws = Workspace(tmp_path / "ws"); ws.ensure()
    sem = lambda target, config, **k: [_cand("sqli", "a.go", 1)]
    cql = lambda target, language, db_dir, **k: [_cand("ssrf", "b.go", 2)]
    res = run_prefilter(ws, str(tmp_path), _profile(), semgrep=sem, codeql=cql,
                        has_tool=lambda n: "/x", qlpack_fn=lambda lang: True)
    assert isinstance(res["coverage"]["languages"], list)
    assert res["coverage"]["languages"][0]["language"] == "go"
    persisted = json.loads((ws.kb / "coverage.json").read_text())
    assert persisted == res["coverage"]


def test_codeql_db_not_left_in_workspace(tmp_path):
    # regression: the CodeQL DB is a large rebuildable artifact and must NOT be
    # written into the (now durable) workspace/memory root.
    ws = Workspace(tmp_path / "ws"); ws.ensure()
    seen = {}
    def cql(target, language, db_dir, **k):
        seen["db_dir"] = db_dir
        return [_cand("ssrf", "b.go", 2)]
    run_prefilter(ws, "tgt", _profile(), semgrep=lambda *a, **k: [], codeql=cql,
                  has_tool=lambda n: "/x", qlpack_fn=lambda lang: True)
    assert "codeql-db" not in "".join(p.name for p in ws.root.iterdir())
    assert str(ws.root) not in seen["db_dir"]   # db built under a temp dir, not memory
