"""Deterministic, regex-based entry-point classification for the Tier-1 graph substrate.

Flags a function/method definition as an external entry point when its body (or, for
Python, its immediately preceding decorator block) matches a route-registration,
user-input-access, CLI-argument, or environment-variable pattern for its language. This
is LLM-free and always computed as part of Tier-1 (see ``graph.build_tier1``) — it gives
``no_path``/``attacker_controls`` a deterministic seed set instead of relying solely on
the LLM-asserted ``scan-profile.json`` ``attack_surface``.
"""

from __future__ import annotations

import re

_ROUTE_PY = re.compile(r"@(?:\w+\.)?(?:route|get|post|put|delete|patch)\s*\(", re.IGNORECASE)
_USER_INPUT_PY = re.compile(r"\brequest\.(?:args|form|json|data|GET|POST|values|files|cookies|headers)\b")
_CLI_ARG_PY = re.compile(r"\bsys\.argv\b|\badd_argument\s*\(")
_ENV_PY = re.compile(r"\bos\.environ\[|\bos\.getenv\(")

_ROUTE_GO = re.compile(r"\.(?:GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc)\s*\(")
_USER_INPUT_GO = re.compile(r"\.URL\.Query\(\)|\.FormValue\(|\.Query\(|\.Param\(")
_CLI_ARG_GO = re.compile(r"\bos\.Args\b|\bflag\.(?:String|Int|Bool)\(")
_ENV_GO = re.compile(r"\bos\.Getenv\(")

_ROUTE_RB = re.compile(r"^\s*(?:get|post|put|patch|delete)\s+['\"]", re.MULTILINE)
_USER_INPUT_RB = re.compile(r"\bparams\[|\brequest\.(?:GET|POST|body)\b")
_CLI_ARG_RB = re.compile(r"\bARGV\b")
_ENV_RB = re.compile(r"\bENV\[")

_ROUTE_PHP = re.compile(r"Route::(?:get|post|put|patch|delete)\s*\(", re.IGNORECASE)
_USER_INPUT_PHP = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b")
_CLI_ARG_PHP = re.compile(r"\$argv\b")
_ENV_PHP = re.compile(r"\bgetenv\(|\$_ENV\[")

_ROUTE_JS = (
    r"\.(?:get|post|put|patch|delete)\s*\(\s*['\"]"
    r"|@(?:Get|Post|Put|Patch|Delete)\s*\("
)
_ROUTE_JS = re.compile(_ROUTE_JS)
_USER_INPUT_JS = re.compile(r"\breq\.(?:query|body|params|headers|cookies)\b")
_CLI_ARG_JS = re.compile(r"\bprocess\.argv\b")
_ENV_JS = re.compile(r"\bprocess\.env\.")

_ROUTE_REASON = "route-decorator: external HTTP route/handler registration"
_USER_INPUT_REASON = "user-input-access: reads request data directly"
_CLI_ARG_REASON = "cli-arg: reads command-line arguments"
_ENV_REASON = "env-var-access: reads environment variables"

_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    "py": [
        (_ROUTE_PY, _ROUTE_REASON),
        (_USER_INPUT_PY, _USER_INPUT_REASON),
        (_CLI_ARG_PY, _CLI_ARG_REASON),
        (_ENV_PY, _ENV_REASON),
    ],
    "go": [
        (_ROUTE_GO, _ROUTE_REASON),
        (_USER_INPUT_GO, _USER_INPUT_REASON),
        (_CLI_ARG_GO, _CLI_ARG_REASON),
        (_ENV_GO, _ENV_REASON),
    ],
    "rb": [
        (_ROUTE_RB, _ROUTE_REASON),
        (_USER_INPUT_RB, _USER_INPUT_REASON),
        (_CLI_ARG_RB, _CLI_ARG_REASON),
        (_ENV_RB, _ENV_REASON),
    ],
    "php": [
        (_ROUTE_PHP, _ROUTE_REASON),
        (_USER_INPUT_PHP, _USER_INPUT_REASON),
        (_CLI_ARG_PHP, _CLI_ARG_REASON),
        (_ENV_PHP, _ENV_REASON),
    ],
}
for _js_lang in ("js", "ts", "jsx", "tsx"):
    _PATTERNS[_js_lang] = [
        (_ROUTE_JS, _ROUTE_REASON),
        (_USER_INPUT_JS, _USER_INPUT_REASON),
        (_CLI_ARG_JS, _CLI_ARG_REASON),
        (_ENV_JS, _ENV_REASON),
    ]


def _decorator_prefix(all_lines: list[str], start: int) -> str:
    """Collect contiguous ``@``-prefixed lines immediately above a 1-indexed ``start`` line.

    Args:
        all_lines: The file's lines (0-indexed list, as from ``str.splitlines()``).
        start: The 1-indexed line where the definition itself begins.

    Returns:
        The contiguous decorator lines directly above ``start``, in original order,
        joined by newlines (empty string if none).
    """
    collected: list[str] = []
    i = start - 2  # 0-indexed line directly above `start`
    while i >= 0 and all_lines[i].strip().startswith("@"):
        collected.append(all_lines[i])
        i -= 1
    return "\n".join(reversed(collected))


def classify_entry_point(lang: str, all_lines: list[str], start: int, end: int) -> str | None:
    """Classify a definition's line span as an entry point, or return ``None``.

    Args:
        lang: Language tag as returned by ``graph._lang_of`` (extension without the dot).
        all_lines: The file's lines (0-indexed list, as from ``str.splitlines()``).
        start: 1-indexed inclusive start line of the definition (from
            ``structural_index.get_function_boundary``).
        end: 1-indexed inclusive end line of the definition.

    Returns:
        A reason string naming the matched category (route-decorator / user-input-access /
        cli-arg / env-var-access), or ``None`` if no pattern matched or the language has no
        pattern table.
    """
    patterns = _PATTERNS.get(lang)
    if not patterns:
        return None
    body = "\n".join(all_lines[start - 1:end])
    if lang == "py":
        prefix = _decorator_prefix(all_lines, start)
        if prefix:
            body = prefix + "\n" + body
    for pattern, reason in patterns:
        if pattern.search(body):
            return reason
    return None
