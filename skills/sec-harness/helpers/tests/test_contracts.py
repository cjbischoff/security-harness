"""Layer-C contract tests: agent-prompt JSON examples must match our real schema.

Catches producer<->schema drift (the finding_id/duplicate_of field-name-drift class)
WITHOUT running an LLM — grep JSON blocks out of the prompt .md files and validate
them against the actual Finding model + gate rules.
"""
import json
import re
from pathlib import Path

import pytest

from sec_harness.findings_gate import validate_findings
from sec_harness.models import Finding
from sec_harness.workspace import Workspace, write_findings

SKILL = Path(__file__).resolve().parents[2]          # skills/sec-harness
AGENTS = SKILL / "agents"
_JSON_BLOCK = re.compile(r"```json\s*\n(.*?)```", re.DOTALL)


def _json_blocks(md_path):
    if not md_path.exists():
        return []
    out = []
    for m in _JSON_BLOCK.finditer(md_path.read_text()):
        raw = m.group(1)
        # tolerate <placeholder> tokens in prompt examples
        cleaned = re.sub(r"<[^>]+>", "null", raw)
        try:
            out.append(json.loads(cleaned))
        except json.JSONDecodeError:
            pass
    return out


def test_investigate_finding_example_matches_model():
    blocks = _json_blocks(AGENTS / "investigate.md")
    finding_blocks = [b for b in blocks if isinstance(b, dict) and "cls" in b and "status" in b]
    assert finding_blocks, "investigate.md must document a Finding JSON example"
    for b in finding_blocks:
        f = Finding.from_dict(b)            # must parse against the REAL model
        assert f.cls and f.id               # required fields present under real names
        # no unknown top-level keys (from_dict would tolerate, so check the drift set)
        allowed = set(Finding.from_dict(b).to_dict().keys())
        assert set(b.keys()) <= allowed, f"prompt example has keys the model drops: {set(b)-allowed}"


def test_investigate_example_passes_the_gate(tmp_path):
    blocks = _json_blocks(AGENTS / "investigate.md")
    finding_blocks = [b for b in blocks if isinstance(b, dict) and "cls" in b and "status" in b]
    ws = Workspace(tmp_path); ws.ensure()
    findings = []
    for i, b in enumerate(finding_blocks, 1):
        f = Finding.from_dict(b); f.id = f"C-{i:04d}"
        if not f.file:
            f.file = "x.py"
        f.line = max(f.line, 1)
        findings.append(f)
    write_findings(ws, findings)
    # the documented example must be gate-clean (no raw+duplicate_of, valid shape)
    assert validate_findings(ws) == []


def test_golden_raw_finding_matches_model():
    golden = SKILL / "helpers" / "fixtures" / "golden_raw_finding.json"
    if not golden.exists():
        pytest.skip("no golden fixture")
    f = Finding.from_dict(json.loads(golden.read_text()))
    assert f.id and f.cls and f.status
