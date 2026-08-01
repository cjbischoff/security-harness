"""Preflight: verify SAST tooling + vendored rules are available.

Checks binaries and rule/pack availability and prints exact Homebrew/setup
commands for anything missing. It never installs — the operator runs the
printed commands.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def default_rules_dir() -> Path:
    """Vendored semgrep rules dir, resolved relative to this package (not CWD).

    Returns:
        Absolute path to the vendored semgrep rules directory.
    """
    return Path(__file__).resolve().parent.parent / "rules" / "semgrep"


# name, purpose, install command (macOS/Homebrew)
TOOLS = [
    ("semgrep", "broad pattern SAST (all languages)", "brew install semgrep"),
    (
        "codeql",
        "semantic dataflow/taint SAST (security-extended suite)",
        "brew install --cask codeql  # then download packs for each language you scan, e.g. codeql pack download codeql/go-queries codeql/python-queries codeql/javascript-queries",
    ),
    ("tree-sitter", "optional: AST-accurate structural index", "brew install tree-sitter"),
    ("ast-grep", "structural AST search (tool-grounded gates + sweep)", "brew install ast-grep"),
    ("osv-scanner", "SCA: dependency CVE scanning (deps class)", "brew install osv-scanner"),
    ("gitleaks", "optional: broad/generic secrets scan (in-house scanner covers distinctive tokens only)", "brew install gitleaks"),
]

# Tools that are nice-to-have but must NOT fail preflight (exit 1) when absent:
# the scan degrades gracefully and records them as skipped rather than crashing.
_OPTIONAL = {"tree-sitter", "osv-scanner", "gitleaks"}

_VENDOR_CMD = (
    "git clone --depth 1 https://github.com/semgrep/semgrep-rules "
    "skills/sec-harness/helpers/rules/semgrep"
)
# Note: _VENDOR_CMD path is repo-root-relative for human manual use


def check_tools(*, which=shutil.which) -> list[dict]:
    """Report presence of each required/optional binary.

    Args:
        which: Injectable ``shutil.which``-style resolver.

    Returns:
        One dict per tool: ``{name, present, install_cmd, purpose}``.
    """
    return [
        {"name": name, "present": which(name) is not None, "install_cmd": cmd, "purpose": purpose}
        for name, purpose, cmd in TOOLS
    ]


def semgrep_rules_present(rules_dir: str | Path) -> bool:
    """Return True if a non-empty vendored semgrep ruleset dir exists.

    Args:
        rules_dir: Directory expected to contain ``semgrep/<lang>/*.yaml``.

    Returns:
        Whether at least one ``.yaml``/``.yml`` rule file exists beneath it.
    """
    base = Path(rules_dir)
    if not base.is_dir():
        return False
    return any(base.rglob("*.yaml")) or any(base.rglob("*.yml"))


# Canonical CodeQL query packs — one per language the harness can drive. A pack
# not published for the installed CodeQL version fails only that pack's download,
# never the others (see the download loop in the CLI caller).
CODEQL_QUERY_LANGS = [
    "actions", "cpp", "csharp", "go", "java", "javascript",
    "python", "ruby", "rust", "swift",
]


def codeql_pack_download_cmd(langs: list[str]) -> str:
    """Return the exact ``codeql pack download`` command for the given languages.

    Args:
        langs: Language ids (e.g. ``["go", "python"]``).

    Returns:
        A single shell command downloading ``codeql/<lang>-queries`` for each.

    Example:
        >>> codeql_pack_download_cmd(["go"])
        'codeql pack download codeql/go-queries'
    """
    return "codeql pack download " + " ".join(f"codeql/{lang}-queries" for lang in langs)


def missing_codeql_packs(installed: list[str], *, all_langs: list[str] | None = None) -> list[str]:
    """Return canonical query-pack languages not present in ``installed``.

    Args:
        installed: Language ids whose pack is already downloaded.
        all_langs: Canonical set to check against; defaults to ``CODEQL_QUERY_LANGS``.

    Returns:
        The missing language ids, in canonical order.
    """
    langs = all_langs if all_langs is not None else CODEQL_QUERY_LANGS
    return [lang for lang in langs if lang not in installed]


def installed_codeql_langs(*, packages_dir: Path | None = None) -> list[str]:
    """List CodeQL languages whose query pack is downloaded.

    The ``codeql`` binary being present does not mean any per-language query
    pack is installed — analysis needs ``codeql/<lang>-queries`` in the local
    cache. Surfacing the installed set lets the operator spot a missing language
    before a scan silently loses that language's dataflow coverage.

    Args:
        packages_dir: Package cache root; defaults to ``~/.codeql/packages``.

    Returns:
        Sorted language ids (e.g. ``["go", "python"]``) with a ``*-queries`` pack.
    """
    base = packages_dir or (Path.home() / ".codeql" / "packages")
    ns = base / "codeql"
    if not ns.is_dir():
        return []
    langs = [p.name[: -len("-queries")] for p in ns.iterdir() if p.name.endswith("-queries")]
    return sorted(langs)


def preflight_report(rules_dir: str | Path, *, which=shutil.which) -> dict:
    """Assemble a preflight report with setup commands for missing pieces.

    Args:
        rules_dir: Root under which vendored semgrep rules should live.
        which: Injectable resolver.

    Returns:
        ``{tools, semgrep_rules, missing, commands}``.
    """
    tools = check_tools(which=which)
    rules_ok = semgrep_rules_present(rules_dir)
    # Optional tools are reported but never block preflight (exit 1) or the scan.
    missing = [t["name"] for t in tools if not t["present"] and t["name"] not in _OPTIONAL]
    commands = [t["install_cmd"] for t in tools if not t["present"] and t["name"] not in _OPTIONAL]
    if not rules_ok:
        commands.append(_VENDOR_CMD)
    return {"tools": tools, "semgrep_rules": rules_ok, "missing": missing, "commands": commands}


def main(argv: list[str] | None = None) -> int:
    """CLI: print the preflight report + any setup commands.

    Args:
        argv: Optional argument vector.

    Returns:
        0 if all tools present and rules vendored, else 1.
    """
    parser = argparse.ArgumentParser(prog="sec-harness-preflight")
    parser.add_argument(
        "--rules-dir",
        default=str(default_rules_dir()),
        help="Where vendored semgrep rules live.",
    )
    args = parser.parse_args(argv)
    rep = preflight_report(args.rules_dir)
    print("sec-harness preflight")
    for t in rep["tools"]:
        mark = "OK" if t["present"] else "MISSING"
        print(f"  [{mark}] {t['name']} — {t['purpose']}")
        if t["name"] == "codeql" and t["present"]:
            langs = installed_codeql_langs()
            listed = ", ".join(langs) if langs else "NONE"
            print(f"       codeql query packs installed: {listed}")
            missing_packs = missing_codeql_packs(langs)
            if missing_packs:
                print("       missing packs — codeql loses dataflow for these languages "
                      "at scan time. Download them with:")
                print(f"         {codeql_pack_download_cmd(missing_packs)}")
    print(f"  [{'OK' if rep['semgrep_rules'] else 'MISSING'}] vendored semgrep rules")
    if rep["commands"]:
        print("\nRun these to complete setup (nothing is installed automatically):")
        for c in rep["commands"]:
            print(f"  {c}")
        return 1
    print("\nAll SAST tooling present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
