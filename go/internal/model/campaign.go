package model

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CampaignState is the persistent per-campaign state enabling resumable,
// multi-pass runs. Field order matches the Python dataclass (models.py:143-146):
// pass_number, active_sha, stages, budget.
type CampaignState struct {
	PassNumber int            `json:"pass_number"`
	ActiveSHA  *string        `json:"active_sha"`
	Stages     Stages         `json:"stages"`
	Budget     map[string]any `json:"budget"`
}

// Stages is an insertion-ordered map of stage name -> status string. The Python
// stages dict is insertion-ordered (e.g. recon, architecture, threat-model,
// prefilter), not alphabetical, so a plain Go map (which marshals sorted) would
// break byte-parity. Stages preserves insertion order on marshal and recovers
// it on unmarshal.
type Stages struct {
	keys []string
	vals map[string]string
}

// Set inserts or updates a stage status, recording insertion order the first
// time a key is seen.
func (s *Stages) Set(key, value string) {
	if s.vals == nil {
		s.vals = make(map[string]string)
	}
	if _, ok := s.vals[key]; !ok {
		s.keys = append(s.keys, key)
	}
	s.vals[key] = value
}

// Get returns the status for a stage and whether it is present.
func (s Stages) Get(key string) (string, bool) {
	v, ok := s.vals[key]
	return v, ok
}

// Keys returns the stage names in insertion order.
func (s Stages) Keys() []string {
	return s.keys
}

// MarshalJSON emits the stages object with keys in insertion order, compact.
// The parent canonical encoder re-indents it with two-space nesting. Strings
// are encoded without HTML escaping so the contract's escaping stays consistent.
func (s Stages) MarshalJSON() ([]byte, error) {
	if len(s.keys) == 0 {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range s.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeJSONString(&buf, k); err != nil {
			return nil, err
		}
		buf.WriteByte(':')
		if err := writeJSONString(&buf, s.vals[k]); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON decodes a JSON object into Stages, capturing key order via a
// token stream so a decoded-then-re-marshaled state preserves the original
// stage order.
func (s *Stages) UnmarshalJSON(data []byte) error {
	s.keys = nil
	s.vals = make(map[string]string)
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("model: stages: expected object, got %v", tok)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("model: stages: non-string key %v", keyTok)
		}
		var val string
		if err := dec.Decode(&val); err != nil {
			return err
		}
		s.Set(key, val)
	}
	// consume closing '}'
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// writeJSONString appends a JSON-encoded string with HTML escaping disabled.
func writeJSONString(buf *bytes.Buffer, s string) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	buf.Write(bytes.TrimRight(b.Bytes(), "\n"))
	return nil
}
