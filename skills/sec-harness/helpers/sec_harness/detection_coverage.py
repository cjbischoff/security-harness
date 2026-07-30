"""Generate an honest, falsifiable detection-coverage doc (F6).

Generated from the live ``clsmap`` inventory so it cannot silently drift from what
the harness can actually classify. States what each backend covers, per-class
confidence, a language matrix, and Known Limitations as fact (not marketing).
"""

from __future__ import annotations

from sec_harness.clsmap import _RULE_ID_CLS, CWE_CLS

# CodeQL language support (security-extended); semgrep is broad/all; sca needs a
# lockfile ecosystem; secrets + template-xss are language-agnostic text scans.
_CODEQL_LANGS = ("go", "python", "javascript", "java", "csharp", "cpp", "ruby", "swift")


def known_classes() -> set[str]:
    """Every attack-class the classifier can emit (CWE map + rule-id router)."""
    return set(CWE_CLS.values()) | set(_RULE_ID_CLS.values())


def _confidence(cls: str) -> str:
    """High if a CWE maps to the class (semantic backing); else Medium."""
    return "High" if cls in set(CWE_CLS.values()) else "Medium"


def generate() -> str:
    """Render the DETECTION_COVERAGE markdown."""
    lines = [
        "# Detection coverage",
        "",
        ("_Generated from the live `clsmap` inventory (`sec_harness.detection_coverage`). "
         "An honest, falsifiable statement of what this harness catches and does not — "
         "not a claim to detect everything._"),
        "",
        "## Rule sources",
        "",
        "| source | what it covers |",
        "|--------|----------------|",
        "| semgrep | broad pattern SAST, all languages; vendored security rulesets |",
        "| codeql | semantic dataflow/taint (`security-extended`), compiled + " + ", ".join(_CODEQL_LANGS),
        "| osv-scanner (sca) | dependency CVEs from lockfiles/manifests |",
        "| secrets (in-house) | distinctive-prefix credentials; broad via optional gitleaks |",
        "| agent + ripgrep | SAST-blind languages (Liquid/templates) + business-logic/hunt-list |",
        "",
        "## Vulnerability classes",
        "",
        "| class | confidence | primary source |",
        "|-------|-----------|----------------|",
    ]
    for cls in sorted(known_classes()):
        src = "sca" if cls == "deps" else ("secrets" if cls == "secrets" else "semgrep/codeql")
        lines.append(f"| {cls} | {_confidence(cls)} | {src} |")
    lines += [
        "",
        "## Language coverage matrix",
        "",
        "| capability | php | python | javascript/ts | go | java | liquid/templates |",
        "|------------|-----|--------|---------------|----|----|------------------|",
        "| semgrep patterns | ✅ | ✅ | ✅ | ✅ | ✅ | — |",
        "| codeql dataflow | — | ✅ | ✅ | ✅ | ✅ | — |",
        "| sca (deps) | ✅ | ✅ | ✅ | ✅ | ✅ | — |",
        "| secrets | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |",
        "| agent + ripgrep (templates/logic) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |",
        "",
        "## Known limitations",
        "",
        "- **CodeQL has no PHP support** — PHP dataflow relies on semgrep patterns only.",
        ("- **Semgrep OSS taint is single-function** — no cross-function/cross-file taint "
         "(that needs Semgrep Pro); the agentic investigate phase covers cross-function paths."),
        ("- **Liquid/Handlebars/ERB templates are SAST-blind** — no CodeQL/semgrep taint; "
         "covered by agent template reads grounded with `ripgrep:` receipts."),
        ("- **SCA/secrets need their tools** — `osv-scanner` for deps (else skipped-and-logged), "
         "optional `gitleaks` for broad secrets (in-house scanner covers distinctive tokens only)."),
        ("- **Business-logic / auth-model classes are agent-found**, not rule-detected — "
         "recall depends on the threat-model hunt list, not SAST."),
    ]
    return "\n".join(lines) + "\n"
