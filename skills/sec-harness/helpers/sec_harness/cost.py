"""Per-run token/cost accounting over CampaignState.budget.

The orchestrator records each subagent's token usage via :func:`record_agent`; the
records live in the existing free-form ``CampaignState.budget`` dict (no contract
change). Token totals are measured; USD is an opt-in estimate from a rates table and is
never auto-rendered as a measured metric.
"""

from __future__ import annotations

from sec_harness.models import CampaignState

# Rough USD per 1M tokens, blended. Estimates only — labelled as such wherever shown.
_RATES_USD_PER_MTOK = {"opus": 15.0, "sonnet": 3.0, "haiku": 0.8, "default": 3.0}


def record_agent(state: CampaignState, phase: str, model: str, tokens: int) -> None:
    """Append one subagent's token usage to the campaign budget.

    Args:
        state: Campaign state to mutate.
        phase: Pipeline phase the agent ran in (e.g. ``"investigate"``).
        model: Model name (e.g. ``"sonnet"``).
        tokens: Total tokens the agent consumed.
    """
    state.budget.setdefault("records", []).append(
        {"phase": phase, "model": model, "tokens": int(tokens)}
    )


def aggregate_by_phase(state: CampaignState) -> dict[str, int]:
    """Sum recorded token usage by phase.

    Args:
        state: Campaign state holding budget records.

    Returns:
        ``{phase: total_tokens}`` (empty when nothing was recorded).
    """
    out: dict[str, int] = {}
    for rec in state.budget.get("records", []):
        out[rec["phase"]] = out.get(rec["phase"], 0) + int(rec.get("tokens", 0))
    return out


def estimate_cost_usd(state: CampaignState, rates: dict[str, float] | None = None) -> float:
    """Estimate run cost in USD from recorded usage and a rates table.

    Args:
        state: Campaign state holding budget records.
        rates: USD per 1M tokens by model, with a ``"default"`` key. Defaults to a
            built-in rough table.

    Returns:
        Estimated USD, rounded to 4 decimals. An estimate, not a measured figure.
    """
    rates = rates or _RATES_USD_PER_MTOK
    total = 0.0
    for rec in state.budget.get("records", []):
        rate = rates.get(rec.get("model", "default"), rates["default"])
        total += int(rec.get("tokens", 0)) / 1_000_000 * rate
    return round(total, 4)
