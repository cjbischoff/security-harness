"""Tests for the ast-grep structural backend."""

import shutil

import pytest

from sec_harness.astgrep import astgrep_available, parse_astgrep_json, run_astgrep

SAMPLE = [
    {"file": "app.py", "range": {"start": {"line": 17, "column": 4}}, "text": "cur.execute(q)"},
]


def test_parse_astgrep_json_1indexes_line():
    out = parse_astgrep_json(SAMPLE)
    assert out == [{"file": "app.py", "line": 18, "text": "cur.execute(q)"}]


def test_run_astgrep_invokes_cli(monkeypatch):
    import json

    class R:
        stdout = json.dumps(SAMPLE)
        returncode = 0

    def fake(cmd, capture_output, text, check):
        assert cmd[0] in ("ast-grep", "sg")
        assert "--pattern" in cmd and "--lang" in cmd and "--json" in cmd
        return R()

    out = run_astgrep("cur.execute($$$)", "python", "root", runner=fake)
    assert out[0]["line"] == 18


@pytest.mark.skipif(shutil.which("ast-grep") is None and shutil.which("sg") is None,
                    reason="ast-grep not installed")
def test_run_astgrep_live_on_fixture():
    from pathlib import Path
    fixture = Path(__file__).parent.parent / "fixtures" / "vulnerable_repo"
    out = run_astgrep("$CUR.execute($$$)", "python", str(fixture))
    assert any(m["file"].endswith("app.py") and m["line"] == 18 for m in out)


@pytest.mark.skipif(not astgrep_available(), reason="ast-grep not installed")
def test_file_root_matches(tmp_path):
    f = tmp_path / "a.ts"
    f.write_text("export function g(x){ return redirect(x, {h:1}); }\n")
    hits = run_astgrep("redirect($$$A)", "typescript", str(f))
    assert len(hits) >= 1
    assert hits[0]["file"].endswith("a.ts")


@pytest.mark.skipif(not astgrep_available(), reason="ast-grep not installed")
def test_dir_root_still_matches(tmp_path):
    (tmp_path / "a.ts").write_text("redirect(y, {h:1});\n")
    hits = run_astgrep("redirect($$$A)", "typescript", str(tmp_path))
    assert len(hits) >= 1


@pytest.mark.skipif(not astgrep_available(), reason="ast-grep not installed")
def test_file_root_excludes_same_named_sibling(tmp_path):
    # a same-basename file at another depth must NOT leak into a single-file query
    target = tmp_path / "index.ts"
    target.write_text("redirect(a, {h:1});\n")
    sub = tmp_path / "nested"
    sub.mkdir()
    (sub / "index.ts").write_text("redirect(b, {h:1});\n")
    hits = run_astgrep("redirect($$$A)", "typescript", str(target))
    assert len(hits) == 1
    assert hits[0]["file"].endswith("index.ts")
    from pathlib import Path
    assert Path(hits[0]["file"]).resolve() == target.resolve()
