"""Tests for per-language SAST coverage accounting."""

from typing import ClassVar


def test_compute_coverage_tiers(tmp_path):
    from sec_harness.coverage import compute_coverage

    (tmp_path / "a.js").write_text("1")
    (tmp_path / "b.liquid").write_text("1")

    class P:
        languages: ClassVar = ["javascript", "liquid"]
        sast_plan: ClassVar = {"codeql": {"run": True, "languages": ["javascript"]},
                     "semgrep": {"run": True, "rulesets": ["rules/semgrep/javascript"]}}

    cov = compute_coverage(P(), ["semgrep", "codeql"], str(tmp_path))
    by = {l["language"]: l for l in cov["languages"]}
    assert by["javascript"]["tier"] == "dataflow"      # codeql covers it
    assert by["liquid"]["tier"] == "none"              # no codeql pack, no semgrep ruleset
    assert "liquid" in cov["uncovered"]
    assert by["javascript"]["files"] == 1 and by["liquid"]["files"] == 1


def test_compute_coverage_pattern_only_when_only_semgrep_covers(tmp_path):
    from sec_harness.coverage import compute_coverage

    (tmp_path / "a.py").write_text("1")

    class P:
        languages: ClassVar = ["python"]
        sast_plan: ClassVar = {"semgrep": {"run": True, "rulesets": ["rules/semgrep/python"]}}

    cov = compute_coverage(P(), ["semgrep"], str(tmp_path))
    by = {l["language"]: l for l in cov["languages"]}
    assert by["python"]["tier"] == "pattern-only"
    assert cov["uncovered"] == []


def test_compute_coverage_backend_not_run_means_no_credit(tmp_path):
    from sec_harness.coverage import compute_coverage

    (tmp_path / "a.js").write_text("1")

    class P:
        languages: ClassVar = ["javascript"]
        sast_plan: ClassVar = {"codeql": {"run": True, "languages": ["javascript"]}}

    # codeql planned but did not actually run (e.g. pack-missing) -> no dataflow credit
    cov = compute_coverage(P(), [], str(tmp_path))
    by = {l["language"]: l for l in cov["languages"]}
    assert by["javascript"]["tier"] == "none"
    assert "javascript" in cov["uncovered"]
