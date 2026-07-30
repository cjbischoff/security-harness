package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Fingerprint returns a stable 12-hex-char fingerprint of a finding's identity:
// sha256("{rule_id}|{cls}|{file}|{line}") truncated to 12 hex chars. It is the
// dedupe/diff identity key, keyed only on RuleID, Cls, File, and Line. Ported
// verbatim from fingerprint.py; byte-identical to the Python oracle (the vector
// r|sqli|app.py|18 hashes to afbc8b946dbd).
func Fingerprint(f Finding) string {
	key := fmt.Sprintf("%s|%s|%s|%d", f.RuleID, f.Cls, f.File, f.Line)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:12]
}
