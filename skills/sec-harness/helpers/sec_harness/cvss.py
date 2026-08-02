"""Deterministic CVSS 3.1 base scoring + an orthogonal OffensivePriority axis.

The LLM proposes a CVSS vector; the score is computed here by the FIRST.org
formula (never LLM arithmetic). OffensivePriority (P1-P4) ranks reachability/
exploitability, kept separate from impact severity. Adapted from VVAH.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _parse(vector: str) -> dict[str, str]:
    """Parse a ``CVSS:3.1/...`` vector into a metric->value dict."""
    parts = vector.split("/")
    metrics = {}
    for p in parts:
        if ":" in p and not p.startswith("CVSS"):
            k, v = p.split(":", 1)
            metrics[k] = v
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        raise ValueError(f"malformed CVSS 3.1 vector: {vector}")
    return metrics


def _roundup(x: float) -> float:
    """CVSS 3.1 roundUp: ceil to one decimal per the spec's integer trick."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def _rating(score: float) -> str:
    """Map a base score to its qualitative band."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def cvss31_base(vector: str) -> tuple[float, str]:
    """Compute the CVSS 3.1 base score and rating for a vector string.

    Args:
        vector: A CVSS 3.1 vector (``CVSS:3.1/AV:.../A:H``).

    Returns:
        ``(base_score, rating)``.

    Raises:
        ValueError: If the vector is missing required base metrics.
    """
    m = _parse(vector)
    try:
        scope_changed = m["S"] == "C"
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    except KeyError as e:
        raise ValueError(f"invalid or missing CVSS 3.1 metric {e}") from e
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0, "None"
    raw = min((1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability), 10)
    score = _roundup(raw)
    return score, _rating(score)


def offensive_priority(vector: str, *, externally_facing: bool = False) -> str:
    """Rank exploitability/reachability P1 (worst) .. P4, orthogonal to severity.

    Args:
        vector: A CVSS 3.1 vector.
        externally_facing: Optional hint that the component is externally reachable.

    Returns:
        ``"P1".."P4"``.
    """
    m = _parse(vector)
    av, pr = m["AV"], m["PR"]
    if av == "N" and pr == "N":
        return "P1"
    if av == "N" and pr == "L":
        return "P2"
    if externally_facing and pr != "H":
        return "P2"
    if av in ("A", "L") or pr == "H":
        return "P3"
    return "P4"
