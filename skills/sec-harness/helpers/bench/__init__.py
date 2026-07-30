"""Dev-only evaluation harness for sec-harness.

Three layers:
  A. Detection benchmark  — corpus (positives/negatives) -> clone@commit -> scan ->
     deterministic-first + LLM-fallback judge -> precision/recall (bench.tally).
  B. Regression corpus    — confirmed findings become locked entries; a locked entry
     that stops being detected is a hard failure (bench.tally.regressions).
  C. Contract/wiring tests — live in the main sec_harness test suite (test_contracts,
     test_wiring), not here.

Not part of the shipped harness — this measures and locks in its quality.
"""
