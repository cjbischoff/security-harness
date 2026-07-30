"""Fail-open parsing helpers (Bucket C6, adapted from audit's json_utils).

The reference tools' hardest-won rule: never silently drop a finding because a parser missed.
Agent output is often JSON wrapped in prose or a ```json fence. These helpers extract it
robustly, and — critically — FAIL OPEN: on any parse failure the caller is told explicitly
(``None`` / a sentinel), never handed a silent empty result it might mistake for "nothing
found". A dropped real finding is the expensive error; surface the failure instead.
"""

from __future__ import annotations

import json


def extract_json(text: str) -> object | None:
    """Extract the first JSON value from ``text``; ``None`` if none parses (fail-open).

    Tries, in order: the whole string; a ```json fenced block; the largest balanced
    ``{...}``/``[...]`` substring (string-literal aware). Returns ``None`` rather than raising
    so the caller must handle "couldn't parse" explicitly instead of silently getting nothing.
    """
    if not text or not text.strip():
        return None
    for candidate in _candidates(text):
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _candidates(text: str):
    """Yield progressively-more-salvaged JSON candidate substrings."""
    yield text.strip()
    fence = _fenced_block(text)
    if fence is not None:
        yield fence
    balanced = _largest_balanced(text)
    if balanced is not None:
        yield balanced


def _fenced_block(text: str) -> str | None:
    """Return the contents of the first ```json … ``` (or bare ``` … ```) fence."""
    lower = text.lower()
    i = lower.find("```json")
    start_marker_len = 7
    if i == -1:
        i = text.find("```")
        start_marker_len = 3
        if i == -1:
            return None
    start = i + start_marker_len
    end = text.find("```", start)
    if end == -1:
        return None
    return text[start:end].strip()


def _largest_balanced(text: str) -> str | None:
    """Return the largest balanced ``{...}`` or ``[...]`` run, ignoring braces in strings."""
    best: str | None = None
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        depth = 0
        start = -1
        in_str = False
        esc = False
        for idx, ch in enumerate(text):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == open_ch:
                if depth == 0:
                    start = idx
                depth += 1
            elif ch == close_ch and depth:
                depth -= 1
                if depth == 0 and start != -1:
                    cand = text[start:idx + 1]
                    if best is None or len(cand) > len(best):
                        best = cand
    return best


def fallback_list(text: str) -> list:
    """Parse ``text`` as a JSON list, or return ``[]`` — but callers should prefer
    :func:`extract_json` and branch on ``None`` so a parse failure is never mistaken for
    an empty result. Provided only for call sites that genuinely want empty-on-failure.
    """
    val = extract_json(text)
    return val if isinstance(val, list) else []
