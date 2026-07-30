package model

import (
	"bytes"
	"encoding/json"
	"strconv"
	"unicode/utf16"
)

// MarshalCanonical serializes v exactly as Python's json.dumps(v, indent=2):
// two-space indent, no HTML escaping of < > &, non-ASCII escaped to \uXXXX
// (ensure_ascii=True, with surrogate pairs for astral runes), and no trailing
// newline. It is the single serializer for all contract objects — never call
// json.MarshalIndent on a Finding or CampaignState.
func MarshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // Python does not escape < > &
	enc.SetIndent("", "  ")  // indent=2
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	b := bytes.TrimRight(buf.Bytes(), "\n") // Encode() appends \n; Python does not
	return escapeNonASCII(b), nil
}

// escapeNonASCII rewrites every rune > 0x7F as \uXXXX (surrogate pairs for
// astral runes), matching Python's ensure_ascii=True. All non-ASCII in valid
// JSON lives inside string literals, so a rune-wise pass over the encoded bytes
// is safe.
func escapeNonASCII(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, r := range string(b) {
		if r < 0x80 {
			out = append(out, byte(r))
			continue
		}
		if r > 0xFFFF {
			r1, r2 := utf16.EncodeRune(r)
			out = append(out, escU(r1)...)
			out = append(out, escU(r2)...)
			continue
		}
		out = append(out, escU(r)...)
	}
	return out
}

// escU formats a single BMP rune as a lowercase \uXXXX escape, matching Python's
// json module.
func escU(r rune) []byte {
	s := strconv.FormatInt(int64(r), 16)
	for len(s) < 4 {
		s = "0" + s
	}
	return []byte(`\u` + s)
}

// EnsureDefaults normalizes the six slice fields to non-nil empty slices so they
// serialize as [] (Python default_factory=list), never null. Call before
// MarshalCanonical on any Finding built in Go or decoded from a dict missing
// those keys.
func (f *Finding) EnsureDefaults() {
	if f.Dataflow == nil {
		f.Dataflow = []string{}
	}
	if f.History == nil {
		f.History = []HistoryEntry{}
	}
	if f.EvidenceSources == nil {
		f.EvidenceSources = []string{}
	}
	if f.ASVSIDs == nil {
		f.ASVSIDs = []string{}
	}
	if f.CodeguardIDs == nil {
		f.CodeguardIDs = []string{}
	}
	if f.Preconditions == nil {
		f.Preconditions = []string{}
	}
}
