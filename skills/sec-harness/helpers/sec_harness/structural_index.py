"""Ripgrep-backed structural index for navigating a target codebase.

Provides symbol definitions, caller sites, and function boundaries using ``rg``
plus lightweight indentation/brace heuristics. This is a navigation aid for the
investigation agents, not a compiler-grade index; it degrades to plain search
and never requires language servers or universal-ctags.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

_PY_DEF = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)")
_JS_FN = re.compile(r"^\s*(?:export\s+)?function\s+([A-Za-z_$][\w$]*)")
_JS_ASSIGN = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?\s*="
)
_JS_FIELD_ARROW = re.compile(
    r"^\s*([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"
)
_DEF_TOKENS = ("def ", "class ", "function ", "const ", "let ", "var ")
_BRACE_EXTS = {".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".c", ".cc", ".cpp", ".h", ".hpp"}


def list_definitions(path: str | Path) -> list[tuple[str, int]]:
    """List symbol definitions in a source file.

    Args:
        path: File to scan.

    Returns:
        ``(name, line)`` pairs (1-indexed) for Python ``def``/``class`` and
        JS/TS ``function``/``const``/``let``/``var`` definitions, in file order.
    """
    out: list[tuple[str, int]] = []
    for i, raw in enumerate(Path(path).read_text().splitlines(), start=1):
        for pat in (_PY_DEF, _JS_FN, _JS_ASSIGN, _JS_FIELD_ARROW):
            m = pat.match(raw)
            if m:
                out.append((m.group(1), i))
                break
    return out


def get_function_boundary(path: str | Path, line: int) -> tuple[int, int]:
    """Estimate the line span of a definition starting at ``line``.

    Uses an indentation heuristic for Python and a brace-balance heuristic for
    C-family/JS/TS/Go. Falls back to a single line for unknown file types.

    Args:
        path: Source file.
        line: 1-indexed line where the definition starts.

    Returns:
        A 1-indexed ``(start, end)`` span (inclusive).
    """
    p = Path(path)
    lines = p.read_text().splitlines()
    idx = line - 1
    if idx < 0 or idx >= len(lines):
        return (line, line)

    if p.suffix in _BRACE_EXTS:
        depth = 0
        seen_brace = False
        for j in range(idx, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                seen_brace = True
            if seen_brace and depth <= 0:
                return (line, j + 1)
        return (line, len(lines))

    if p.suffix == ".py":
        base = len(lines[idx]) - len(lines[idx].lstrip())
        end = idx
        for j in range(idx + 1, len(lines)):
            stripped = lines[j].strip()
            if not stripped:
                continue
            indent = len(lines[j]) - len(lines[j].lstrip())
            if indent <= base:
                break
            end = j
        return (line, end + 1)

    # ponytail: unknown language -> single line; extend heuristics if a new
    # target language shows up in a real scan.
    return (line, line)


def find_callers(symbol: str, root: str, *, runner=subprocess.run) -> list[str]:
    """Find call sites of ``symbol`` under ``root`` (definition lines excluded).

    Args:
        symbol: Symbol name to search for (matched as a whole word).
        root: Directory to search.
        runner: Injectable subprocess runner (for testing).

    Returns:
        ``"path:line"`` strings for each match that is not a definition of
        ``symbol``.
    """
    completed = runner(
        ["rg", "--no-heading", "--line-number", "--word-regexp", symbol, root],
        capture_output=True,
        text=True,
        check=False,
    )
    call_re = re.compile(r"\b" + re.escape(symbol) + r"\s*\(")
    prod: list[str] = []
    test: list[str] = []
    for row in completed.stdout.splitlines():
        parts = row.split(":", 2)
        if len(parts) < 3:
            continue
        path, lineno, text = parts
        if any(tok + symbol in text for tok in _DEF_TOKENS):
            continue
        if not call_re.search(text):
            continue
        # Tag test/fixture call sites so an investigator can tell a real
        # production caller from noise (a symbol with 1 prod + 27 test callers
        # is common). Production callers are returned first.
        (test if _is_test_path(path) else prod).append(f"{path}:{lineno}")
    return prod + [f"{c} (test)" for c in test]


_TEST_MARKERS = ("/test/", "/tests/", "/__tests__/", "/__mocks__/", "/fixtures/",
                 "/spec/", ".test.", ".spec.", "_test.", "test_", "e2e", "cypress", "playwright")


def _is_test_path(path: str) -> bool:
    """Return True if ``path`` looks like test/fixture/spec code, not production.

    Args:
        path: A file path.

    Returns:
        Whether the path matches a common test/fixture marker.
    """
    p = path.replace("\\", "/").lower()
    base = p.rsplit("/", 1)[-1]
    return any(m in p for m in _TEST_MARKERS if m.startswith("/") or m in ("e2e", "cypress", "playwright")) \
        or any(m in base for m in (".test.", ".spec.", "_test.", "test_"))


def main(argv: list[str] | None = None) -> int:
    """CLI for the structural index (used by investigation agents).

    Subcommands: ``defs``, ``boundary``, ``callers``.

    Args:
        argv: Optional argument vector.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-index")
    sub = parser.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("defs", help="List definitions in a file.")
    d.add_argument("--path", required=True)

    b = sub.add_parser("boundary", help="Print the (start end) span of a definition.")
    b.add_argument("--path", required=True)
    b.add_argument("--line", type=int, required=True)

    c = sub.add_parser("callers", help="List call sites of a symbol under a root.")
    c.add_argument("--symbol", required=True)
    c.add_argument("--root", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "defs":
        for name, line in list_definitions(args.path):
            print(f"{name}\t{line}")
        return 0
    if args.cmd == "boundary":
        start, end = get_function_boundary(args.path, args.line)
        print(f"{start} {end}")
        src = Path(args.path).read_text().splitlines()
        for ln in range(start, end + 1):
            print(f"{ln}: {src[ln - 1]}")
        return 0
    if args.cmd == "callers":
        for c in find_callers(args.symbol, args.root):
            print(c)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
