package model

import "strings"

// mechanical is the set of genuine tool-receipt source heads. A source whose
// head (before the first ":") is in this set — and which is not llm-namespaced —
// is a mechanical receipt. Ported verbatim from evidence.py:14 (the eight
// sources); this is a security control, not a feature, so the set is frozen.
var mechanical = map[string]bool{
	"semgrep":          true,
	"codeql":           true,
	"ast-grep":         true,
	"tree-sitter":      true,
	"ripgrep":          true,
	"structural-index": true,
	"secrets":          true,
	"sca":              true,
}

// Confidence is a finding's tier, derived from its strongest evidence source.
// Values match the Python Confidence enum exactly.
type Confidence string

// Confidence tiers, matching the Python Confidence enum values.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// IsToolReceipt reports whether source is a genuine mechanical-tool receipt.
//
// Any source with an "llm" prefix is rejected before the mechanical-set check,
// so an LLM assertion can never be counted as a receipt. Otherwise the head
// (before the first ":") must be one of the eight mechanical sources. Ported
// verbatim from evidence.py is_tool_receipt.
func IsToolReceipt(source string) bool {
	if strings.HasPrefix(source, "llm") {
		return false
	}
	head, _, _ := strings.Cut(source, ":")
	return mechanical[head]
}

// AsLLMClaim namespaces an LLM-asserted source so it cannot masquerade as a
// receipt: the source is returned unchanged if already "llm"-prefixed, else it
// is prefixed with "llm-claimed:". Ported verbatim from evidence.py as_llm_claim.
func AsLLMClaim(source string) string {
	if strings.HasPrefix(source, "llm") {
		return source
	}
	return "llm-claimed:" + source
}

// ConfidenceFor grades a finding from its evidence sources (strongest link):
// any real tool receipt yields High; else any "llm-corroborated"-prefixed source
// yields Medium; else Low. This is the confirm gate — an llm-claimed-only finding
// can never reach High. Ported verbatim from evidence.py confidence_for.
func ConfidenceFor(sources []string) Confidence {
	for _, s := range sources {
		if IsToolReceipt(s) {
			return ConfidenceHigh
		}
	}
	for _, s := range sources {
		if strings.HasPrefix(s, "llm-corroborated") {
			return ConfidenceMedium
		}
	}
	return ConfidenceLow
}
