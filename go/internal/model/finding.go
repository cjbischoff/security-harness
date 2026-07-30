// Package model is the frozen inter-phase data contract for the security-harness
// Go port. It defines the Finding schema, the CampaignState resume object, and a
// single canonical JSON serializer proven byte-identical to the Python
// sec_harness contract (to_dict() + json.dumps(indent=2)).
package model

// Severity is a normalized finding severity level. Its string values are the
// verbatim Python Severity enum values (models.py).
type Severity string

// Severity levels, matching the Python Severity enum values exactly.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// FindingStatus is a finding's lifecycle status driving the FP-reduction ladder
// and multi-pass logic. Its string values match the Python FindingStatus enum.
type FindingStatus string

// Finding lifecycle statuses, matching the Python FindingStatus enum values exactly.
const (
	StatusCandidate              FindingStatus = "candidate"
	StatusRaw                    FindingStatus = "raw"
	StatusConfirmed              FindingStatus = "confirmed"
	StatusRejected               FindingStatus = "rejected"
	StatusFixed                  FindingStatus = "fixed"
	StatusStale                  FindingStatus = "stale"
	StatusDuplicate              FindingStatus = "duplicate"
	StatusNeedsDeploymentTesting FindingStatus = "needs-deployment-testing"
)

// Finding is a single security finding at a point in its lifecycle. It is the
// frozen contract consumed by every later phase.
//
// Field declaration order is LOCKED to the Python dataclass field order
// (models.py:83-110): Go marshals struct fields in declaration order and the
// canonical serializer requires it to equal Python's asdict() key order. No
// field carries omitempty — the Python contract emits every field (empty list →
// [], empty string → "", None → null). Optional scalars are pointers so a zero
// value serializes as null rather than 0/"".
type Finding struct {
	ID                 string         `json:"id"`
	RuleID             string         `json:"rule_id"`
	Cls                string         `json:"cls"`
	Status             FindingStatus  `json:"status"`
	Severity           Severity       `json:"severity"`
	File               string         `json:"file"`
	Line               int            `json:"line"`
	Message            string         `json:"message"`
	Dataflow           []string       `json:"dataflow"`
	RiskScore          *int           `json:"risk_score"`
	Verification       *string        `json:"verification"`
	PatchDiff          *string        `json:"patch_diff"`
	DiscoverySHA       *string        `json:"discovery_sha"`
	DuplicateOf        *string        `json:"duplicate_of"`
	History            []HistoryEntry `json:"history"`
	Fingerprint        *string        `json:"fingerprint"`
	Priority           *string        `json:"priority"`
	CVSSVector         *string        `json:"cvss_vector"`
	Evidence           string         `json:"evidence"`
	EvidenceSources    []string       `json:"evidence_sources"`
	ASVSIDs            []string       `json:"asvs_ids"`
	CodeguardIDs       []string       `json:"codeguard_ids"`
	CompletenessTier   *string        `json:"completeness_tier"`
	RuntimeDisposition *string        `json:"runtime_disposition"`
	RuntimeTest        *RuntimeTest   `json:"runtime_test"`
	Preconditions      []string       `json:"preconditions"`
	Reachability       *Reachability  `json:"reachability"`
	JudgeVerdict       *string        `json:"judge_verdict"`
}

// Reachability is the trace-phase verdict on whether a finding is reachable.
// Key order is verified: reachable, blocker, chain.
type Reachability struct {
	Reachable bool     `json:"reachable"`
	Blocker   *string  `json:"blocker"`
	Chain     []string `json:"chain"`
}

// RuntimeTest is the optional manual runtime-test directive built by the
// red-team phase. Key order per models.py:72-73: objective, preconditions,
// payloads, expected_signal, telemetry.
type RuntimeTest struct {
	Objective      string   `json:"objective"`
	Preconditions  []string `json:"preconditions"`
	Payloads       []string `json:"payloads"`
	ExpectedSignal string   `json:"expected_signal"`
	Telemetry      string   `json:"telemetry"`
}

// HistoryEntry is one append-only per-pass event log entry. Python builds these
// as plain dicts, so only the keys set at each append site are emitted; every
// field therefore carries omitempty and pointer ints distinguish absent (nil)
// from a real zero value.
//
// Field order makes every history shape observed in the Python core a
// subsequence, so a decoded entry re-marshals in Python key order:
//
//	{pass, event}                     — fixtures / investigate
//	{event}                           — verify.py, dedupe.py, campaign.py
//	{event, reason}                   — campaign.py (salvaged)
//	{event, field, value}             — factcheck.py (corrected)
//	{event, claimed, derived, delta}  — calibrate.py (severity-inflated)
//	{event, verify_status, source_doc} — context.py (control-verification)
type HistoryEntry struct {
	Pass         *int   `json:"pass,omitempty"`
	Event        string `json:"event,omitempty"`
	Note         string `json:"note,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Field        string `json:"field,omitempty"`
	Value        string `json:"value,omitempty"`
	Claimed      string `json:"claimed,omitempty"`
	Derived      *int   `json:"derived,omitempty"`
	Delta        *int   `json:"delta,omitempty"`
	VerifyStatus string `json:"verify_status,omitempty"`
	SourceDoc    string `json:"source_doc,omitempty"`
}
