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


def test_cross_repo_adversary_prompt_exists_and_carries_rules():
    p = Path(__file__).resolve().parents[2] / "agents" / "cross-repo-adversary.md"
    txt = p.read_text().lower()
    assert "deterministic" in txt          # promote needs a deterministic join
    assert "tool receipt" in txt or "mechanical" in txt
    assert "weaken" in txt or "demote" in txt  # reasoning-only can only weaken/demote
    assert "promote" in txt


def test_correlate_combiner_prompt_exists_and_carries_rules():
    p = Path(__file__).resolve().parents[2] / "agents" / "correlate-combiner.md"
    txt = p.read_text().lower()
    assert "narrative" in txt                        # fills narrative markers only
    assert "must not" in txt and ("mermaid" in txt or "diagram" in txt)  # don't touch diagrams
    assert "evidence_chain" in txt or "evidence chain" in txt            # cite provenance
    assert "$shell_var" in txt or "shell_var" in txt                     # no literal secrets
    for slot in ("architecture", "threat_model", "redteam", "findings"):
        assert slot in txt.replace("-", "_")         # names the four docs


def test_finding_template_documents_triage_ndt_dep_views():
    p = Path(__file__).resolve().parents[2] / "references" / "finding-template.md"
    txt = p.read_text().lower()
    assert "triage line" in txt                       # skim layer documented
    assert "ndt-view" in txt or "needs-runtime view" in txt
    assert "dep-view" in txt or "dependency view" in txt
    assert "reachability" in txt                       # dep-view binding
    assert "renumber" in txt                           # condensed tier no-gap note
