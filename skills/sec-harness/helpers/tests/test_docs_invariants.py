from __future__ import annotations

from pathlib import Path

_SKILL = Path(__file__).resolve().parents[2] / "SKILL.md"
_CONSTS = Path(__file__).resolve().parents[2] / "references" / "prompt-constants.md"


def test_skill_documents_scope_tokens():
    txt = _SKILL.read_text()
    assert "{{REPO_ROOT}}" in txt
    assert "{{SCAN_SCOPE}}" in txt


def test_prompt_constants_states_repo_root_invariant():
    txt = _CONSTS.read_text().lower()
    assert "repo-root-relative" in txt
    assert "repo_root" in txt


def test_skill_documents_methodology_playbook():
    txt = _SKILL.read_text()
    assert "adversary_depth" in txt
    assert "gate-by-exception" in txt
    assert "model_tier_map" in txt
    # family-diversity must remain a hard invariant, not a knob
    assert "family" in txt.lower()
