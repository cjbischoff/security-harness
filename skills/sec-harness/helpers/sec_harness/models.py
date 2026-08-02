"""Core data models shared across all sec-harness phases.

The ``Finding`` schema defined here is the frozen contract consumed by every
later phase (investigation, FP-reduction ladder, remediation, reporting).
Verification values: ``verified-static | static-only | not-fixed | verify-error``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Normalized severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    """Lifecycle status driving the FP-reduction ladder and multi-pass logic."""

    CANDIDATE = "candidate"
    RAW = "raw"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    FIXED = "fixed"
    STALE = "stale"
    DUPLICATE = "duplicate"
    # Real-but-unprovable-from-source (infra/proxy/cache/secret we cannot read). A
    # terminal state that is NOT confirmed and NOT a false positive (F9); reported in
    # its own section so an unconfirmable HIGH is never fudged to a confirmed MEDIUM.
    NEEDS_DEPLOYMENT_TESTING = "needs-deployment-testing"
    # Low-value vendored-rule hit (O-027): terminal, never re-run, never enters the
    # confirmed report or the FP ladder as `raw`.
    INFORMATIONAL = "informational"


@dataclass
class Finding:
    """A single security finding at a point in its lifecycle.

    Attributes:
        id: Stable harness-assigned identifier (e.g. ``F-0001``).
        rule_id: Originating detector rule id.
        cls: Attack class (e.g. ``sqli``, ``secrets``, ``ssrf``).
        status: Current lifecycle status.
        severity: Normalized severity.
        file: Repo-relative path.
        line: 1-indexed line number.
        message: Human-readable description.
        dataflow: Ordered source->sink evidence steps.
        risk_score: Calibrated 1-10 score (set in a later phase).
        verification: Verification status (set in a later phase).
        patch_diff: Proposed fix diff (set in a later phase).
        discovery_sha: Git SHA the finding was discovered against.
        duplicate_of: Primary finding id if this was merged as a duplicate.
        history: Append-only per-pass event log.
        fingerprint: Stable content hash for deduplication.
        priority: Offensive priority level (P1-P4).
        cvss_vector: Proposed CVSS 3.1 vector string.
        evidence: Raw evidence snippet (e.g. code line, stack trace).
        evidence_sources: Namespaced evidence sources (e.g. ``codeql:dataflow``, ``llm-claimed:reachable``).
        asvs_ids: OWASP ASVS 5.0 requirement ids this finding violates (advisory, F1).
        codeguard_ids: CodeGuard rule ids this finding relates to (advisory, F1).
        completeness_tier: Fix completeness (FULL|MITIGATION|WORKAROUND) on fixed findings (F11).
        runtime_disposition: Red-team phase classification of a confirmed finding —
            ``static-settled`` (source-provable, no live test adds certainty) or
            ``needs-runtime`` (high-confidence statically, exploitability needs a live check).
        runtime_test: Optional manual runtime-test directive built by the red-team phase
            (``objective``/``preconditions``/``payloads``/``expected_signal``/``telemetry``).
        preconditions: What must hold for the finding to be exploitable (auth state, config,
            local access). Drives the precondition severity cap in calibrate (more/harder
            preconditions → lower risk), per the reference-tool severity-from-preconditions rule.
        reachability: Trace-phase verdict — ``{"reachable": bool, "blocker": str|None,
            "chain": [file:line]}``. ``blocker`` ∈ sanitizer|auth_check|input_validation|
            dead_code|feature_flag|other. Feeds the red-team static-vs-runtime discrimination.
        judge_verdict: Cheap adjudicator's call after finder+critic (e.g. ``uphold`` /
            ``downgrade`` / ``severity-inflated``), a triage-ordering signal.
        runtime_dependent: True when the only barrier to confirmation is data not in the
            repo (catalog contents, a live host, whether a committed secret is live). Marks
            a genuine runtime lead for ``campaign.promote_runtime_dependent`` (O-010/O-021).
    """

    id: str
    rule_id: str
    cls: str
    status: FindingStatus
    severity: Severity
    file: str
    line: int
    message: str
    dataflow: list[str] = field(default_factory=list)
    risk_score: int | None = None
    verification: str | None = None
    patch_diff: str | None = None
    discovery_sha: str | None = None
    duplicate_of: str | None = None
    history: list[dict] = field(default_factory=list)
    fingerprint: str | None = None
    priority: str | None = None
    cvss_vector: str | None = None
    evidence: str = ""
    evidence_sources: list[str] = field(default_factory=list)
    asvs_ids: list[str] = field(default_factory=list)
    codeguard_ids: list[str] = field(default_factory=list)
    completeness_tier: str | None = None
    runtime_disposition: str | None = None
    runtime_test: dict | None = None
    preconditions: list[str] = field(default_factory=list)
    reachability: dict | None = None
    judge_verdict: str | None = None
    runtime_dependent: bool = False

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict (enums become their string values)."""
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        """Deserialize from a dict produced by :meth:`to_dict`.

        Tolerates unknown keys (forward-compat): a finding written by a newer schema
        loads under an older one, dropping fields it doesn't know.
        """
        d = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        d["status"] = FindingStatus(d["status"])
        d["severity"] = Severity(d["severity"])
        return cls(**d)


@dataclass
class CampaignState:
    """Persistent per-campaign state enabling resumable, multi-pass runs.

    Attributes:
        pass_number: 1-indexed current pass.
        active_sha: Git SHA pinned for the current pass.
        stages: Map of stage name -> status string (e.g. ``done``).
        budget: Token-budget accounting (``spent_tokens``, ``cap``).
    """

    pass_number: int
    active_sha: str | None
    stages: dict[str, str] = field(default_factory=dict)
    budget: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> CampaignState:
        """Deserialize from a dict produced by :meth:`to_dict`."""
        return cls(**d)
