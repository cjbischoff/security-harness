from sec_harness import cost
from sec_harness.models import CampaignState


def _state():
    return CampaignState(pass_number=1, active_sha="s", stages={}, budget={})


def test_record_and_aggregate_by_phase():
    st = _state()
    cost.record_agent(st, "investigate", "sonnet", 1000)
    cost.record_agent(st, "investigate", "sonnet", 500)
    cost.record_agent(st, "validate", "opus", 2000)
    assert cost.aggregate_by_phase(st) == {"investigate": 1500, "validate": 2000}


def test_estimate_cost_usd_uses_rates():
    st = _state()
    cost.record_agent(st, "validate", "opus", 1_000_000)
    usd = cost.estimate_cost_usd(st, rates={"opus": 15.0, "default": 3.0})
    assert usd == 15.0


def test_aggregate_empty_budget_is_empty():
    assert cost.aggregate_by_phase(_state()) == {}
