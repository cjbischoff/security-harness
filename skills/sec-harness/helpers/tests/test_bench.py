"""Tests for the bench eval harness (corpus, judge, tally, run)."""
import json

from bench.adapter import WorkspaceAdapter, reportable
from bench.corpus import Corpus, CorpusEntry, load_corpus
from bench.judge import deterministic_match, judge_all, judge_entry
from bench.run import run_benchmark
from bench.tally import tally
from sec_harness.models import Finding, FindingStatus, Severity
from sec_harness.workspace import Workspace, write_findings


def _entry(fid, **kw):
    d = {"finding_id": fid, "kind": "positive", "source": "real-confirmed", "cls": "xss",
         "repo_url": "https://github.com/o/r", "commit": "a" * 40, "file": "app.js",
         "line": 10, "description": "d"}
    d.update(kw)
    return CorpusEntry(**d)


def _f(id_, cls, file, line, status=FindingStatus.CONFIRMED, message="m", rule_id="r"):
    return Finding(id=id_, rule_id=rule_id, cls=cls, status=status,
                   severity=Severity.HIGH, file=file, line=line, message=message)


# ---- corpus ----
def test_corpus_validate_and_grouping():
    c = Corpus([_entry("V1"), _entry("V2", kind="negative"),
                _entry("V3", repo_url="ftp://bad", commit="")])
    errs = c.validate()
    assert any("V3" in e for e in errs)         # bad url + missing commit
    assert len(c.positives()) == 2 and len(c.negatives()) == 1
    assert len(c.by_repo()) == 2                 # V3 differs by commit


def test_corpus_load(tmp_path):
    (tmp_path / "r.json").write_text(json.dumps([_entry("V1").__dict__]))
    c = load_corpus(tmp_path)
    assert c.entries[0].finding_id == "V1"


# ---- judge ----
def test_deterministic_match_class_file_line():
    e = _entry("V1", file="app.js", line=10, cls="xss")
    assert deterministic_match(e, [_f("C1", "xss", "src/app.js", 14)]) is not None   # within window
    assert deterministic_match(e, [_f("C1", "xss", "src/app.js", 99)]) is None        # too far
    assert deterministic_match(e, [_f("C1", "sqli", "src/app.js", 10)]) is None       # wrong class


def test_deterministic_match_dep_cve():
    e = _entry("V1", source="dep-cve", cls="deps", cve="GHSA-xxxx")
    assert deterministic_match(e, [_f("C1", "deps", "pkg.json", 1, rule_id="osv:GHSA-xxxx")]) is not None


def test_judge_positive_negative_and_llm_fallback():
    pos = _entry("V1", kind="positive")
    neg = _entry("V2", kind="negative")
    findings = [_f("C1", "xss", "app.js", 10)]
    rp = judge_entry(pos, findings); assert rp.detected and rp.is_correct and rp.method == "deterministic"
    # negative WRONGLY flagged -> detected True -> is_correct False (a false positive)
    rn = judge_entry(neg, findings); assert rn.detected is True and rn.is_correct is False
    # no deterministic match + llm fallback used
    called = {}
    def llm(entry, fs):
        called["x"] = True
        return True, "fuzzy root-cause match"
    r = judge_entry(_entry("V9", file="other.js"), findings, llm_judge=llm)
    assert called and r.method == "llm" and r.detected


# ---- tally ----
def test_tally_segments_and_regressions():
    entries = [_entry("V1", source="real-confirmed"),
               _entry("V2", source="synthetic"),
               _entry("V3", source="real-confirmed", kind="negative"),
               _entry("V4", source="real-confirmed", lifecycle="locked")]
    corpus = Corpus(entries)
    # V1 detected, V2 missed, V3 wrongly flagged (FP), V4 (locked) MISSED -> regression
    findings_by_repo = {("https://github.com/o/r", "a" * 40):
                        [_f("C1", "xss", "app.js", 10)]}   # matches V1/V3 loc; V2/V4 same loc too
    # make V2 (synthetic) and V4 not match by putting them on a different line
    entries[1].line = 500; entries[3].line = 600
    results = judge_all(entries, findings_by_repo)
    sc = tally(results, corpus)
    assert "V3" in sc.false_positives
    assert "V4" in sc.regressions and sc.to_dict()["regressed"] is True
    assert "synthetic" in sc.by_source and "real-confirmed" in sc.by_source
    assert "REGRESSIONS" in sc.to_markdown()


# ---- run (end-to-end with injected clone + workspace adapter) ----
def test_run_benchmark_end_to_end(tmp_path):
    corpus_dir = tmp_path / "corpus"; corpus_dir.mkdir()
    (corpus_dir / "r.json").write_text(json.dumps([
        _entry("V1", file="app.js", line=10).__dict__,
        _entry("V2", kind="negative", file="safe.js", line=5, cls="sqli").__dict__,
    ]))
    # pre-populate a workspace with the scan's findings; WorkspaceAdapter reads it
    scanned = Workspace(tmp_path / "pre"); scanned.ensure()
    write_findings(scanned, [_f("C1", "xss", "app.js", 10)])
    adapter = WorkspaceAdapter(lambda repo: scanned)
    clones = []
    def fake_clone(url, commit, dest):
        clones.append((url, commit)); dest.mkdir(parents=True, exist_ok=True); return dest
    sc = run_benchmark(corpus_dir, tmp_path / "run", adapter, clone_fn=fake_clone)
    assert sc["overall"]["tp"] == 1 and sc["overall"]["fp"] == 0
    assert (tmp_path / "run" / "scorecard.md").exists()
    assert clones  # cloned once
    # resume: second run skips clone (cache hit)
    clones.clear()
    run_benchmark(corpus_dir, tmp_path / "run", adapter, clone_fn=fake_clone)
    assert clones == []


def test_reportable_filters_status(tmp_path):
    ws = Workspace(tmp_path); ws.ensure()
    write_findings(ws, [_f("C1", "xss", "a.js", 1, status=FindingStatus.CONFIRMED),
                        _f("C2", "xss", "a.js", 2, status=FindingStatus.REJECTED)])
    assert [f.id for f in reportable(ws)] == ["C1"]


def test_seed_corpus_is_valid():
    from pathlib import Path

    from bench.corpus import load_corpus
    seed = Path(__file__).resolve().parents[1] / "bench" / "corpus_seed"
    c = load_corpus(seed)
    assert c.validate() == []
    assert len(c.positives()) >= 5 and len(c.negatives()) >= 3
    assert any(e.source == "dep-cve" for e in c.entries)
