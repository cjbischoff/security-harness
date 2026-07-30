"""Tests for evidence grading + tool-vs-LLM receipt distinction."""

from sec_harness.evidence import Confidence, as_llm_claim, confidence_for, is_tool_receipt


def test_is_tool_receipt():
    assert is_tool_receipt("codeql:dataflow") is True
    assert is_tool_receipt("ast-grep:sink") is True
    assert is_tool_receipt("structural-index:callers") is True
    assert is_tool_receipt("llm-claimed:codeql") is False   # cannot masquerade
    assert is_tool_receipt("llm-inferred") is False


def test_as_llm_claim_namespaces():
    assert as_llm_claim("codeql") == "llm-claimed:codeql"
    assert as_llm_claim("llm-inferred") == "llm-inferred"    # already llm-prefixed


def test_confidence_ladder():
    assert confidence_for(["codeql:dataflow", "llm-inferred"]) is Confidence.HIGH
    assert confidence_for(["llm-corroborated"]) is Confidence.MEDIUM
    assert confidence_for(["llm-inferred"]) is Confidence.LOW
    assert confidence_for([]) is Confidence.LOW
