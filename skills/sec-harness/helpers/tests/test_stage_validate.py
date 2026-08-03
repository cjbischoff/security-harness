"""Tests for sec_harness.stage_validate — per-stage output validation routing."""

from __future__ import annotations


def test_discovery_ledger_stage_is_validated():
    from sec_harness.discovery_ledger import new_ledger
    from sec_harness.stage_validate import validate_stage
    assert validate_stage("discovery-ledger", new_ledger()) == []
    bad = new_ledger(); bad["terminal_reason"] = "nope"
    assert validate_stage("discovery-ledger", bad)


def test_coverage_ledger_stage_is_validated():
    from sec_harness.stage_validate import validate_stage
    good = {"completeness": "partial", "surfaces": [{"id": "a", "disposition": "reported"}]}
    assert validate_stage("coverage-ledger", good) == []
    bad = {"completeness": "complete", "surfaces": [], "deferred": ["x"]}
    assert validate_stage("coverage-ledger", bad)
