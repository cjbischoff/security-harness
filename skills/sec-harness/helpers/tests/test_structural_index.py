"""Tests for the ripgrep-backed structural index."""

from pathlib import Path

from sec_harness.structural_index import (
    find_callers,
    get_function_boundary,
    list_definitions,
)

STRUCT = Path(__file__).parent / "fixtures_struct"


def test_list_definitions_python():
    defs = dict(list_definitions(STRUCT / "sample.py"))
    assert defs["alpha"] == 1
    assert defs["beta"] == 7
    assert "Gamma" in defs


def test_list_definitions_js():
    defs = dict(list_definitions(STRUCT / "sample.js"))
    assert "alpha" in defs
    assert "beta" in defs


def test_list_definitions_finds_typed_const_arrow(tmp_path):
    p = tmp_path / "a.ts"
    p.write_text(
        "export const handler: RequestHandler = async (req, res) => {\n"
        "  return tool(req)\n"
        "}\n\nfunction tool(x) { return x }\n"
    )
    names = {n for n, _ in list_definitions(p)}
    assert "handler" in names


def test_list_definitions_finds_class_field_arrow(tmp_path):
    p = tmp_path / "b.js"
    p.write_text(
        "class Foo {\n  bar = () => {\n    return baz()\n  }\n}\n\n"
        "function baz() { return 1 }\n"
    )
    names = {n for n, _ in list_definitions(p)}
    assert "bar" in names
    guard = tmp_path / "c.js"
    guard.write_text("x = 5\n")
    assert "x" not in {n for n, _ in list_definitions(guard)}


def test_get_function_boundary_python_indent():
    # alpha starts line 1, body ends before the blank line / next def
    start, end = get_function_boundary(STRUCT / "sample.py", 1)
    assert start == 1
    assert end == 4  # last line of alpha's body ("    return 0")


def test_get_function_boundary_js_braces():
    start, end = get_function_boundary(STRUCT / "sample.js", 1)
    assert start == 1
    assert end == 6  # closing brace of alpha


def test_find_callers_excludes_definition(monkeypatch):
    rg_output = f"{STRUCT}/sample.py:8:    return alpha(5) + alpha(6)\n{STRUCT}/sample.py:1:def alpha(x):\n"

    class R:
        stdout = rg_output
        returncode = 0

    def fake_run(cmd, capture_output, text, check):
        assert cmd[0] == "rg"
        assert "-w" in cmd or "--word-regexp" in cmd
        return R()

    callers = find_callers("alpha", str(STRUCT), runner=fake_run)
    assert any("sample.py:8" in c for c in callers)
    assert not any("sample.py:1" in c for c in callers)  # definition excluded


def test_find_callers_excludes_js_const_definition():
    rg_output = "x/sample.js:9:  return beta();\nx/sample.js:8:const beta = () => {\n"

    class R:
        stdout = rg_output
        returncode = 0

    callers = find_callers("beta", "x", runner=lambda *a, **k: R())
    assert any("sample.js:9" in c for c in callers)
    assert not any("sample.js:8" in c for c in callers)


def test_cli_defs_lists_symbols(capsys):
    from sec_harness.structural_index import main

    rc = main(["defs", "--path", str(STRUCT / "sample.py")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "alpha\t1" in out
    assert "beta\t7" in out


def test_cli_boundary(capsys):
    from sec_harness.structural_index import main

    rc = main(["boundary", "--path", str(STRUCT / "sample.py"), "--line", "1"])
    out = capsys.readouterr().out
    assert rc == 0
    lines = out.strip().split('\n')
    assert lines[0] == "1 4"  # header with start and end
    assert len(lines) == 5  # header + 4 source lines


def test_callers_requires_call_shape():
    out = "\n".join([
        "app/x.ts:3:import { multipass } from './m'",   # import, not a call
        "app/y.ts:9:  const u = multipass(token)",        # real call
        "app/z.ts:1:// multipass docs mention",           # prose
    ])

    class R:
        stdout = out
        returncode = 0

    got = find_callers("multipass", "app", runner=lambda *a, **k: R())
    assert got == ["app/y.ts:9"]


def test_boundary_returns_source(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("def g():\n    return 1\n\nx = 2\n")
    start, end = get_function_boundary(f, 1)
    assert (start, end) == (1, 2)


def test_find_callers_tags_test_paths_prod_first():
    from sec_harness.structural_index import find_callers

    class R:
        stdout = (
            "src/app.py:10:    foo()\n"
            "tests/test_app.py:5:    foo()\n"
            "src/services/x.js:22:    foo()\n"
            "cypress/e2e/spec.cy.js:3:    foo()\n"
        )
        stderr = ""; returncode = 0

    out = find_callers("foo", "/r", runner=lambda *a, **k: R())
    # production callers first, unmarked; test callers after, marked (test)
    assert out[0] == "src/app.py:10"
    assert out[1] == "src/services/x.js:22"
    assert all("(test)" in c for c in out[2:])
    assert any("tests/test_app.py" in c for c in out)
    assert any("cypress/e2e" in c for c in out)


def test_is_test_path():
    from sec_harness.structural_index import _is_test_path
    assert _is_test_path("src/foo/bar.py") is False
    assert _is_test_path("app/tests/x.py") is True
    assert _is_test_path("a/b.test.ts") is True
    assert _is_test_path("test_foo.py") is True
    assert _is_test_path("playwright/login.js") is True
