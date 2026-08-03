from sec_harness import discovery_ledger as dl
from sec_harness.workspace import Workspace


def test_new_finding_resets_streak_no_new_increments():
    led = dl.new_ledger(k=2, max_waves=5)
    dl.record_wave(led, ["a", "b"])          # 2 new
    assert led["consecutive_no_new"] == 0
    dl.record_wave(led, ["a"])               # no new (already seen)
    assert led["consecutive_no_new"] == 1
    assert led["terminal_reason"] is None
    dl.record_wave(led, ["b"])               # still no new -> saturated at k=2
    assert led["terminal_reason"] == "saturated"
    assert dl.is_terminal(led)


def test_capped_when_max_waves_reached_without_saturation():
    led = dl.new_ledger(k=99, max_waves=3)
    for i in range(3):
        dl.record_wave(led, [f"fp{i}"])      # always new, never saturates
    assert led["terminal_reason"] == "capped"


def test_save_and_load_roundtrip(tmp_path):
    ws = Workspace(root=tmp_path / "ws"); ws.ensure()
    led = dl.new_ledger()
    dl.record_wave(led, ["x"])
    dl.save_ledger(ws, led)
    assert dl.load_ledger(ws)["waves"] == led["waves"]


def test_validate_rejects_bad_terminal_reason():
    led = dl.new_ledger()
    led["terminal_reason"] = "bogus"
    assert any("terminal_reason" in e for e in dl.validate_discovery_ledger(led))
    assert dl.validate_discovery_ledger(dl.new_ledger()) == []
