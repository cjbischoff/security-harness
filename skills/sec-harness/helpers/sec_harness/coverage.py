"""Per-language SAST coverage accounting: dataflow vs pattern-only vs none (O-007/O-033)."""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict


class _LangCoverage(TypedDict):
    """One language's coverage record."""

    language: str
    files: int
    tier: str

# language -> source extensions (lowercased, no dot). Only languages the harness reasons about.
_LANG_EXT: dict[str, tuple[str, ...]] = {
    "javascript": ("js", "jsx", "mjs", "cjs"), "typescript": ("ts", "tsx"),
    "python": ("py",), "go": ("go",), "java": ("java",), "ruby": ("rb",),
    "php": ("php",), "csharp": ("cs",), "cpp": ("c", "cc", "cpp", "cxx", "h", "hpp"),
    "rust": ("rs",), "swift": ("swift",), "liquid": ("liquid",), "scss": ("scss",),
    "html": ("html", "htm"), "graphql": ("graphql", "gql"),
}
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor",
              ".sec-harness", "__pycache__", "coverage"}


def _count_files(target: str, lang: str) -> int:
    """Count source files under ``target`` matching ``lang``'s known extensions."""
    exts = _LANG_EXT.get(lang, ())
    if not exts:
        return 0
    root = Path(target)
    n = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.suffix.lower().lstrip(".") in exts:
            n += 1
    return n


def _semgrep_langs(sast_plan: dict) -> set[str]:
    """Languages implied by the semgrep ruleset paths (``rules/semgrep/<lang>``)."""
    langs: set[str] = set()
    for rs in ((sast_plan.get("semgrep") or {}).get("rulesets") or []):
        parts = str(rs).rstrip("/").split("/")
        if len(parts) >= 2 and parts[-2] == "semgrep":
            langs.add(parts[-1])
    return langs


def compute_coverage(profile, backends_run: list[str], target: str) -> dict:
    """Per-language coverage tier from the profile + which backends actually ran.

    Args:
        profile: A ``ScanProfile``-shaped object exposing ``languages`` and ``sast_plan``.
        backends_run: Backend names that actually ran (``run_prefilter``'s ``backends_run``) —
            a backend merely *planned* in ``sast_plan`` earns no credit unless it ran.
        target: Source root to count files under.

    Returns:
        ``{"languages": [{"language", "files", "tier"}, ...], "dataflow_pct": int,
        "uncovered": [str, ...]}`` where ``tier`` is ``"dataflow"`` (CodeQL ran for that
        language), ``"pattern-only"`` (semgrep ruleset covers it, no CodeQL), or ``"none"``
        (LLM shape-hunting only). ``uncovered`` lists ``none``-tier languages with files present.
    """
    sast_plan = getattr(profile, "sast_plan", None) or {}
    codeql_langs = set((sast_plan.get("codeql") or {}).get("languages") or []) \
        if "codeql" in backends_run else set()
    semgrep_langs = _semgrep_langs(sast_plan) if "semgrep" in backends_run else set()
    langs: list[_LangCoverage] = []
    for lang in (getattr(profile, "languages", []) or []):
        if lang in codeql_langs:
            tier = "dataflow"
        elif lang in semgrep_langs:
            tier = "pattern-only"
        else:
            tier = "none"
        langs.append({"language": lang, "files": _count_files(target, lang), "tier": tier})
    total = sum(l["files"] for l in langs) or 1
    dataflow_files = sum(l["files"] for l in langs if l["tier"] == "dataflow")
    return {
        "languages": langs,
        "dataflow_pct": round(100 * dataflow_files / total),
        "uncovered": [l["language"] for l in langs if l["tier"] == "none" and l["files"] > 0],
    }
