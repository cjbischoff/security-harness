from sec_harness.coverage_ledger import render_markdown, validate_coverage_ledger


def _ledger(completeness, surfaces, deferred=None):
    return {"completeness": completeness, "surfaces": surfaces, "deferred": deferred or []}


def test_complete_forbids_needs_follow_up():
    d = _ledger("complete", [{"id": "auth", "disposition": "needs_follow_up"}])
    errs = validate_coverage_ledger(d)
    assert any("needs_follow_up" in e for e in errs)


def test_complete_forbids_nonempty_deferred():
    d = _ledger("complete", [{"id": "auth", "disposition": "reported"}], deferred=["templates"])
    assert any("deferred" in e for e in validate_coverage_ledger(d))


def test_consistent_complete_ledger_is_valid():
    d = _ledger("complete", [{"id": "auth", "disposition": "reported"}])
    assert validate_coverage_ledger(d) == []


def test_bad_disposition_flagged():
    d = _ledger("partial", [{"id": "auth", "disposition": "bogus"}])
    assert any("disposition" in e for e in validate_coverage_ledger(d))


def test_render_markdown_lists_deferred():
    d = _ledger("partial", [{"id": "auth", "disposition": "reported"}], deferred=["liquid templates"])
    md = render_markdown(d)
    assert "Coverage completeness" in md and "liquid templates" in md
