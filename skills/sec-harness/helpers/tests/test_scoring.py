"""Tests for deterministic fix-validation scoring."""

from sec_harness.scoring import score_fix


def _g(root="pass", cov="pass", nonew="pass", best="pass"):
    return {"root_cause": root, "instance_coverage": cov,
            "no_new_vulnerabilities": nonew, "best_practices": best}


def test_all_pass_is_fixed():
    verdict, score = score_fix(_g())
    assert verdict == "fixed" and score >= 0.99


def test_regression_gate_caps_verdict():
    # everything else perfect, but a regression fails -> cannot be "fixed"
    verdict, _ = score_fix(_g(nonew="fail"))
    assert verdict in ("partial", "not_fixed")


def test_regression_skip_is_unverifiable():
    assert score_fix(_g(nonew="skip"))[0] == "unverifiable"


def test_coverage_floor_unverifiable():
    # skip the 3 non-critical gates; only no_new_vulnerabilities evaluated (0.19 < 0.50)
    verdict, _ = score_fix(_g(root="skip", cov="skip", best="skip"))
    assert verdict == "unverifiable"


def test_invalid_is_fail_closed():
    _, score = score_fix(_g(best="invalid"))
    assert score < 1.0    # invalid scores 0 but stays in denominator
