"""Tests for CodeQL config trust gating."""

from sec_harness.codeql import codeql_config_trusted


def test_trusted_when_no_config(tmp_path):
    ok, _ = codeql_config_trusted(tmp_path)
    assert ok is True


def test_untrusted_on_custom_extractor(tmp_path):
    (tmp_path / "qlpack.yml").write_text("name: x\nextractor: evil\n")
    ok, reason = codeql_config_trusted(tmp_path)
    assert ok is False and "extractor" in reason


def test_untrusted_on_build_hook(tmp_path):
    gh = tmp_path / ".github" / "codeql"; gh.mkdir(parents=True)
    (gh / "codeql-config.yml").write_text("queries:\n  - uses: ./local\nbuildCommand: make evil\n")
    ok, _ = codeql_config_trusted(tmp_path)
    assert ok is False
