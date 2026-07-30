"""Tests for F1: ASVS + CodeGuard loaders + rule-matcher."""
from sec_harness.asvs import AsvsCatalog, default_catalog_path
from sec_harness.codeguard import default_codeguard_dir, load_rules
from sec_harness.rule_matcher import build_guided_context, match_function


def test_asvs_seed_loads_and_indexes():
    c = AsvsCatalog.load(default_catalog_path())
    assert len(c.requirements) >= 10
    assert c.get("1.2.5").full_id == "v5.0.0-1.2.5"
    assert [r.id for r in c.by_cwe("CWE-78")] == ["1.2.5"]
    assert "1.2.5" in c.format_for_prompt(["1.2.5"])


def test_codeguard_seed_loads():
    r = load_rules(default_codeguard_dir())
    assert "codeguard-0-cryptography" in r
    cg = r["codeguard-0-cryptography"]
    assert "javascript" in cg.languages
    assert cg.format_for_prompt()  # non-empty bullet body


def test_match_function_routes_apis_and_names():
    assert match_function("os.system(x)", "run", "python").asvs_ids == ["1.2.5"]
    assert "6.2.3" in match_function("hashlib.md5(p)", "h", "python").asvs_ids
    assert match_function("cursor.execute(q)", "q", "python").asvs_ids  # sqli
    # function-name signal alone (empty-ish body)
    m = match_function("pass", "authorize_user", "python")
    assert "4.1.1" in m.asvs_ids
    # C-unsafe gated on language
    assert "codeguard-0-safe-c-functions" in match_function("strcpy(a,b)", "f", "c").codeguard_ids
    assert match_function("strcpy(a,b)", "f", "python").matched is False  # not C -> no match


def test_no_match_lets_guided_skip():
    m = match_function("return a + b", "add", "python")
    assert m.matched is False   # guided mode skips the LLM for this function


def test_build_guided_context_injects_both():
    c = AsvsCatalog.load(default_catalog_path())
    r = load_rules(default_codeguard_dir())
    m = match_function("os.system(x)", "run", "python")
    ctx = build_guided_context(m, c, r)
    assert "ASVS" in ctx and "1.2.5" in ctx and "CodeGuard" in ctx


def test_compliance_renders_in_report():
    from sec_harness.models import Finding, FindingStatus, Severity
    from sec_harness.report import render_finding
    f = Finding(id="C1", rule_id="r", cls="cmdi", status=FindingStatus.CONFIRMED,
                severity=Severity.HIGH, file="a.py", line=1, message="m",
                evidence_sources=["semgrep:x"], asvs_ids=["v5.0.0-1.2.5"],
                codeguard_ids=["codeguard-0-input-validation-injection"])
    md = render_finding(f)
    assert "Compliance" in md and "ASVS v5.0.0-1.2.5" in md
