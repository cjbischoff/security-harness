package model

import "testing"

// TestEvidenceGate proves the receipt/confidence gate: mechanical receipts reach
// High, an llm-claimed-only finding cannot, and AsLLMClaim namespaces raw sources.
func TestEvidenceGate(t *testing.T) {
	receipts := []string{"semgrep:rules.x", "secrets:aws", "sca:CVE-1", "ripgrep:pat",
		"codeql:dataflow", "ast-grep:p", "tree-sitter:n", "structural-index:i"}
	for _, s := range receipts {
		if !IsToolReceipt(s) {
			t.Errorf("IsToolReceipt(%q) = false, want true", s)
		}
	}

	notReceipts := []string{"llm-claimed:reachable", "llm-anything", "llm-corroborated", "unknown:x"}
	for _, s := range notReceipts {
		if IsToolReceipt(s) {
			t.Errorf("IsToolReceipt(%q) = true, want false", s)
		}
	}

	if got := ConfidenceFor([]string{"llm-claimed:reachable"}); got != ConfidenceLow {
		t.Errorf("ConfidenceFor([llm-claimed:reachable]) = %q, want %q", got, ConfidenceLow)
	}
	if got := ConfidenceFor([]string{"semgrep:rules.x"}); got != ConfidenceHigh {
		t.Errorf("ConfidenceFor([semgrep:rules.x]) = %q, want %q", got, ConfidenceHigh)
	}
	if got := ConfidenceFor([]string{"llm-corroborated"}); got != ConfidenceMedium {
		t.Errorf("ConfidenceFor([llm-corroborated]) = %q, want %q", got, ConfidenceMedium)
	}

	if got := AsLLMClaim("reachable"); got != "llm-claimed:reachable" {
		t.Errorf("AsLLMClaim(reachable) = %q, want llm-claimed:reachable", got)
	}
	if got := AsLLMClaim("llm-corroborated"); got != "llm-corroborated" {
		t.Errorf("AsLLMClaim(llm-corroborated) = %q, want llm-corroborated", got)
	}

	// Confirm-gate assertion: an llm-claimed-only finding can never reach High.
	if got := ConfidenceFor([]string{"llm-claimed:reachable"}); got == ConfidenceHigh {
		t.Error("confirm gate breached: llm-claimed-only reached ConfidenceHigh")
	}
	if got := ConfidenceFor([]string{"semgrep:rules.sqli"}); got != ConfidenceHigh {
		t.Errorf("mechanical receipt did not reach High: got %q", got)
	}
}
