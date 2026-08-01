"""Tests for the preflight tool checker."""


from sec_harness.preflight import (
    check_tools,
    default_rules_dir,
    preflight_report,
    semgrep_rules_present,
)


def test_check_tools_reports_presence():
    fake_which = lambda name: "/usr/bin/" + name if name == "semgrep" else None
    rows = {r["name"]: r for r in check_tools(which=fake_which)}
    assert rows["semgrep"]["present"] is True
    assert rows["codeql"]["present"] is False
    assert "brew" in rows["codeql"]["install_cmd"]


def test_semgrep_rules_present(tmp_path):
    assert semgrep_rules_present(tmp_path / "nope") is False
    d = tmp_path / "semgrep" / "python"
    d.mkdir(parents=True)
    (d / "r.yaml").write_text("rules: []")
    assert semgrep_rules_present(tmp_path) is True


def test_preflight_report_lists_missing_commands(tmp_path):
    fake_which = lambda name: None  # nothing installed
    rep = preflight_report(tmp_path, which=fake_which)
    assert "codeql" in rep["missing"]
    assert any("codeql" in c for c in rep["commands"])
    assert rep["semgrep_rules"] is False


def test_default_rules_dir_is_package_relative():
    d = default_rules_dir()
    assert d.name == "semgrep" and d.parent.name == "rules"
    assert d.is_absolute()


def test_report_finds_vendored_rules_regardless_of_cwd():
    # rules exist under helpers/rules/semgrep in this repo
    rep = preflight_report(default_rules_dir())
    assert rep["semgrep_rules"] is True


def test_installed_codeql_langs(tmp_path):
    from sec_harness.preflight import installed_codeql_langs
    assert installed_codeql_langs(packages_dir=tmp_path / "nope") == []
    ns = tmp_path / "codeql"
    (ns / "javascript-queries").mkdir(parents=True)
    (ns / "python-queries").mkdir(parents=True)
    (ns / "not-a-pack").mkdir(parents=True)
    assert installed_codeql_langs(packages_dir=tmp_path) == ["javascript", "python"]


def test_codeql_pack_download_cmd():
    from sec_harness.preflight import codeql_pack_download_cmd
    cmd = codeql_pack_download_cmd(["go", "python"])
    assert cmd == "codeql pack download codeql/go-queries codeql/python-queries"


def test_missing_codeql_packs():
    from sec_harness.preflight import CODEQL_QUERY_LANGS, missing_codeql_packs
    # nothing installed -> every canonical pack is missing
    assert missing_codeql_packs([]) == CODEQL_QUERY_LANGS
    # some installed -> only the rest are missing, order preserved
    rest = missing_codeql_packs(["python", "go"])
    assert "python" not in rest and "go" not in rest
    assert rest == [lang for lang in CODEQL_QUERY_LANGS if lang not in ("python", "go")]
