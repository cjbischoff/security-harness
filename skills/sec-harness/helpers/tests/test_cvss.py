"""Tests for deterministic CVSS 3.1 base scoring + OffensivePriority."""

import pytest

from sec_harness.cvss import cvss31_base, offensive_priority

CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
MED = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"


def test_cvss_known_vectors():
    score, rating = cvss31_base(CRIT)
    assert score == 9.8 and rating == "Critical"
    score2, rating2 = cvss31_base(MED)
    assert 0.1 <= score2 < 4.0 and rating2 == "Low"


def test_cvss_malformed_raises():
    with pytest.raises(ValueError):
        cvss31_base("not-a-vector")


def test_offensive_priority():
    assert offensive_priority(CRIT) == "P1"                       # unauth + network
    assert offensive_priority(MED) == "P2"                        # network + low-priv
    assert offensive_priority("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H") == "P3"


def test_invalid_metric_value_raises_valueerror():
    # 'M' is not a legal Confidentiality value (N/L/H) — must be ValueError, not KeyError (O-029).
    with pytest.raises(ValueError):
        cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:H/A:N")


def test_valid_vector_still_scores():
    score, rating = cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert round(score) == 10
    assert rating == "Critical"
