"""Deterministic ASVS/CodeGuard rule-matcher pre-filter (F1).

Maps code — dangerous-API-call regexes + function-name patterns, per language — to
ASVS 5.0 requirement IDs + CodeGuard rule IDs, with NO LLM call. Two payoffs:
guided mode skips the LLM for functions with no rule match (token cut), and every
match yields citable compliance IDs (ASVS control + CodeGuard rule) alongside CWE.

Tables are intentionally hand-curated and conservative — a false match just wastes a
prompt or over-cites; it never confirms a finding (ASVS/CodeGuard tags are advisory,
NOT tool receipts).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# (regex, [asvs_ids]) — dangerous sinks -> the ASVS requirement they implicate.
API_TO_ASVS: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"Runtime\.getRuntime\(\)\.exec\(|\bos\.system\(|subprocess\.|child_process|\bexec\(|shell_exec\("), ["1.2.5"]),
    (re.compile(r"\bexecute\(|cursor\.execute|createQuery\(|rawQuery\(|\bquery\(.*%|f[\"'].*SELECT"), ["1.2.4"]),
    (re.compile(r"\bmd5\b|\bsha1\b|\bDES\b|MODE_ECB|mcrypt_"), ["6.2.3"]),
    (re.compile(r"pickle\.loads|yaml\.load\b|unserialize\(|readObject\(|Marshal\.load"), ["1.5.2"]),
    (re.compile(r"innerHTML|dangerouslySetInnerHTML|document\.write|\.html\("), ["1.3.1"]),
    (re.compile(r"requests\.(get|post)\(|urlopen\(|axios\.|fetch\(|curl_exec\("), ["1.2.6"]),
    (re.compile(r"open\(|readFile|send_file|os\.path\.join\(.*request|\.\./"), ["1.11.2"]),
    (re.compile(r"jwt\.decode\(|verify=False|algorithms=\[|alg.*none"), ["3.5.3"]),
]

# (regex, [codeguard_ids]) — same sinks -> the CodeGuard knowledge file.
API_TO_CODEGUARD: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"exec\(|subprocess|os\.system|shell_exec|child_process|\bquery\(|execute\("), ["codeguard-0-input-validation-injection"]),
    (re.compile(r"\bmd5\b|\bsha1\b|\bDES\b|MODE_ECB|mcrypt_|Random\(\)"), ["codeguard-0-cryptography"]),
    (re.compile(r"innerHTML|dangerouslySetInnerHTML|document\.write"), ["codeguard-0-client-side-web-security"]),
    (re.compile(r"open\(|readFile|send_file|upload|multipart"), ["codeguard-0-file-handling-and-uploads"]),
    (re.compile(r"api[_-]?key|secret|token|password"), ["codeguard-1-hardcoded-credentials"]),
]

# function-name -> {asvs, codeguard} (a second, body-independent signal).
NAME_PATTERNS: list[tuple[re.Pattern, dict]] = [
    (re.compile(r"(?i)auth|login|signin|logout|session"), {"asvs": ["6.1.1", "3.1.1"], "codeguard": ["codeguard-0-authorization-access-control"]}),
    (re.compile(r"(?i)authorize|access|permission|role|admin|owner"), {"asvs": ["4.1.1"], "codeguard": ["codeguard-0-authorization-access-control"]}),
    (re.compile(r"(?i)encrypt|decrypt|hash|sign|verify|token"), {"asvs": ["6.2.1"], "codeguard": ["codeguard-0-cryptography"]}),
    (re.compile(r"(?i)webhook|callback|notify"), {"asvs": ["1.2.6"], "codeguard": ["codeguard-0-api-web-services"]}),
]

# C/C++ memory-unsafe functions (substring check, gated on language).
_C_UNSAFE = ("strcpy", "strcat", "sprintf", "gets", "memcpy", "system(", "scanf")


@dataclass
class MatchResult:
    """Which standards a function implicates + why."""

    asvs_ids: list[str] = field(default_factory=list)
    codeguard_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return bool(self.asvs_ids or self.codeguard_ids)


def match_function(code: str, func_name: str = "", language: str = "") -> MatchResult:
    """Match a function body + name against the standards tables.

    Args:
        code: The function body (or a code snippet).
        func_name: The function's name (drives NAME_PATTERNS).
        language: Lowercase language id (enables C-specific checks).

    Returns:
        A :class:`MatchResult` (``.matched`` is False when nothing matched — the
        signal guided mode uses to skip the LLM).
    """
    asvs: list[str] = []
    cg: list[str] = []
    reasons: list[str] = []
    for pat, ids in API_TO_ASVS:
        if pat.search(code):
            asvs += ids
            reasons.append(f"api:{pat.pattern[:24]}")
    for pat, ids in API_TO_CODEGUARD:
        if pat.search(code):
            cg += ids
    for pat, hit in NAME_PATTERNS:
        if func_name and pat.search(func_name):
            asvs += hit.get("asvs", [])
            cg += hit.get("codeguard", [])
            reasons.append(f"name:{func_name}")
    if language in ("c", "cpp") and any(u in code for u in _C_UNSAFE):
        asvs.append("1.2.5")
        cg.append("codeguard-0-safe-c-functions")
        reasons.append("c-unsafe-fn")
    return MatchResult(sorted(set(asvs)), sorted(set(cg)), reasons)


def build_guided_context(match: MatchResult, asvs_catalog=None, codeguard_rules=None,
                         max_cg_chars: int = 800) -> str:
    """Render matched ASVS + CodeGuard guidance for injection into a guided prompt.

    Args:
        match: The :class:`MatchResult`.
        asvs_catalog: Optional :class:`sec_harness.asvs.AsvsCatalog`.
        codeguard_rules: Optional ``{rule_id: CodeguardRule}``.
        max_cg_chars: Per-rule CodeGuard body budget.

    Returns:
        A prompt-ready block (empty string if nothing matched / no data provided).
    """
    parts = []
    if asvs_catalog and match.asvs_ids:
        text = asvs_catalog.format_for_prompt(match.asvs_ids)
        if text:
            parts.append("Relevant ASVS 5.0 requirements:\n" + text)
    if codeguard_rules and match.codeguard_ids:
        for cid in match.codeguard_ids:
            r = codeguard_rules.get(cid)
            if r:
                parts.append(f"CodeGuard [{cid}]:\n" + r.format_for_prompt(max_cg_chars))
    return "\n\n".join(parts)
