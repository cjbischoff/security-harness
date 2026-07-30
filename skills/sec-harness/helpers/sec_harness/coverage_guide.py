"""Coverage-guided stop condition for the multi-pass campaign (F7).

Auto-stop only when BOTH hold: coverage is complete (every attack-surface class was
investigated to a terminal disposition) AND yield is below threshold (few/no new
confirmed findings this pass). Yield-alone stopping quits with blind spots; coverage-
alone never converges. Requiring both is the defensible criterion.
"""

from __future__ import annotations


def coverage_complete(attack_surface: list[str], investigated: set[str]) -> bool:
    """True if every non-``deps`` attack-surface class has been investigated.

    Args:
        attack_surface: The profile's ``attack_surface`` classes.
        investigated: Classes that reached a terminal disposition this campaign.

    Returns:
        Whether coverage is complete.
    """
    required = {c for c in attack_surface if c != "deps"}
    return required.issubset(investigated)


def should_stop(attack_surface: list[str], investigated: set[str],
                new_confirmed_this_pass: int, *, yield_threshold: int = 1) -> bool:
    """Return True when the campaign may auto-stop.

    Args:
        attack_surface: Profile attack-surface classes.
        investigated: Classes investigated to a terminal disposition.
        new_confirmed_this_pass: Count of NEW confirmed findings this pass.
        yield_threshold: Stop only when new confirmed < this (default 1 = zero-new).

    Returns:
        ``coverage_complete AND (new_confirmed_this_pass < yield_threshold)``.
    """
    return coverage_complete(attack_surface, investigated) and \
        new_confirmed_this_pass < yield_threshold
