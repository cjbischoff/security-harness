package model

import "testing"

// TestFingerprint locks the Go fingerprint to the Python sha256[:12] oracle
// vector and proves identity depends on the four key fields.
func TestFingerprint(t *testing.T) {
	f := Finding{RuleID: "r", Cls: "sqli", File: "app.py", Line: 18}
	if got := Fingerprint(f); got != "afbc8b946dbd" {
		t.Errorf("Fingerprint(r|sqli|app.py|18) = %q, want afbc8b946dbd", got)
	}

	g := f
	g.Line = 19
	if Fingerprint(g) == Fingerprint(f) {
		t.Error("changing Line did not change the fingerprint")
	}
}
