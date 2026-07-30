package model

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// readGolden reads a byte-target file from testdata, failing the test if absent.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v (run: python3 bench/gen_golden.py)", name, err)
	}
	return b
}

// assertByteEqual reports a byte mismatch with a first-diff pointer.
func assertByteEqual(t *testing.T, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	n := min(len(got), len(want))
	i := 0
	for i < n && got[i] == want[i] {
		i++
	}
	t.Errorf("byte mismatch at offset %d (got %d bytes, want %d bytes)\n got: %q\nwant: %q",
		i, len(got), len(want), snippet(got, i), snippet(want, i))
}

// snippet returns a short window around offset i for diagnostics.
func snippet(b []byte, i int) []byte {
	start := max(i-20, 0)
	end := min(i+20, len(b))
	return b[start:end]
}

// TestParity proves the Go Finding marshals byte-identically to the Python
// to_dict() golden for the minimal, full, and nested fixtures: read golden ->
// decode -> EnsureDefaults -> MarshalCanonical -> assert byte-equal.
func TestParity(t *testing.T) {
	for _, name := range []string{"finding_min", "finding_full", "finding_nested"} {
		t.Run(name, func(t *testing.T) {
			golden := readGolden(t, name+".golden.json")
			var f Finding
			if err := json.Unmarshal(golden, &f); err != nil {
				t.Fatalf("unmarshal %s: %v", name, err)
			}
			f.EnsureDefaults()
			got, err := MarshalCanonical(f)
			if err != nil {
				t.Fatalf("marshal %s: %v", name, err)
			}
			assertByteEqual(t, got, golden)
		})
	}
}

// TestTolerantDecode proves a partial/extra-key finding decodes without error
// (unknown keys ignored, missing keys defaulted) and re-marshals to the Python
// tolerant-decode-then-canonical byte-target.
func TestTolerantDecode(t *testing.T) {
	raw := readGolden(t, "finding_raw_input.json")
	var f Finding
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("tolerant decode failed: %v", err)
	}
	f.EnsureDefaults()
	got, err := MarshalCanonical(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertByteEqual(t, got, readGolden(t, "partial_roundtrip.golden.json"))
}
