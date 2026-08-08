"""The ScanProfile contract emitted by recon and consumed by all later phases.

Recon writes this to ``workspace/kb/scan-profile.json``; it parameterizes SAST
selection, which attack-class agents spawn, and per-pass budget caps.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class ScanProfile:
    """Adaptive configuration derived from reconnaissance of the target repo.

    Attributes:
        languages: Detected programming languages (lowercase).
        frameworks: Detected frameworks/libraries of security interest.
        entrypoints: ``file:symbol`` external entry points (routes, handlers, main).
        runnable: Whether the repo declares a build/run path (informational; the
            harness never executes the target).
        attack_surface: Attack classes plausibly present (keys of attack-classes.md).
        sast_plan: Which SAST backends to run and how (semgrep/codeql/sca/secrets).
        agents_to_spawn: Attack-class investigation agents to launch in Plan 3.
        budget_hint: Per-pass caps (e.g. ``max_candidates``, ``max_investigate_agents``).
        notes: Optional free-form structured signals recon carries forward that no
            typed field captures — e.g. ``{"eol_frameworks": ["Zend Framework 1",
            "Ember 1.13"]}`` flags an unmaintained (EOL) stack, itself
            security-relevant. Downstream phases may read it; never required.
        subsystems: Input-processing subsystem partition (parsers, protocol stages,
            endpoints, auth) recon carves the attack surface into, so parallel investigators
            are distributed ACROSS distinct code rather than converging on the same shallow
            bugs. Each item: ``{"name": str, "paths": [str], "why": str}``. Optional.
        attack_surface_evidence: Maps each ``attack_surface`` key to the ``file:line``
            indicators that justified including it, so the phase gate can challenge
            unevidenced classes. Optional; an absent or empty entry routes to
            adversary judgment rather than auto-rejecting.
        scan_options: Optional process knobs the orchestrator reads: ``adversary_depth``
            (``full`` | ``gate-by-exception``), ``model_tier_map`` (phase→tier),
            ``wave_k``/``max_waves`` (investigate saturation), ``token_budget``.
            Never required; absent ⇒ full depth + defaults.
    """

    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    runnable: bool = False
    attack_surface: list[str] = field(default_factory=list)
    sast_plan: dict = field(default_factory=dict)
    agents_to_spawn: list[str] = field(default_factory=list)
    budget_hint: dict = field(default_factory=dict)
    notes: dict = field(default_factory=dict)
    subsystems: list[dict] = field(default_factory=list)
    attack_surface_evidence: dict[str, list[str]] = field(default_factory=dict)
    scan_options: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> ScanProfile:
        """Deserialize from a dict (unknown keys rejected by the dataclass)."""
        return cls(**d)


_LIST_STR_FIELDS = ("languages", "frameworks", "entrypoints", "attack_surface", "agents_to_spawn")
_DICT_FIELDS = ("sast_plan", "budget_hint")
_OPTIONAL_DICT_FIELDS = ("scan_options",)
_REQUIRED = (*_LIST_STR_FIELDS, "runnable", *_DICT_FIELDS)


def validate_profile(d: dict) -> list[str]:
    """Validate a scan-profile dict against the ScanProfile contract.

    Args:
        d: Parsed profile dict.

    Returns:
        A list of error messages; empty if the profile is valid.
    """
    errors: list[str] = []
    for key in _REQUIRED:
        if key not in d:
            errors.append(f"missing required field: {key}")
    for key in _LIST_STR_FIELDS:
        val = d.get(key)
        if key in d and (not isinstance(val, list) or not all(isinstance(x, str) for x in val)):
            errors.append(f"field {key} must be a list of strings")
    if "runnable" in d and not isinstance(d["runnable"], bool):
        errors.append("field runnable must be a boolean")
    for key in _DICT_FIELDS:
        if key in d and not isinstance(d[key], dict):
            errors.append(f"field {key} must be an object")
    for key in _OPTIONAL_DICT_FIELDS:
        if key in d and not isinstance(d[key], dict):
            errors.append(f"field {key} must be an object")
    return errors


def load_profile(path: str | Path) -> ScanProfile:
    """Load and validate a scan-profile JSON file.

    Args:
        path: Path to the profile JSON.

    Returns:
        The parsed :class:`ScanProfile`.

    Raises:
        ValueError: If the profile fails validation.
    """
    d = json.loads(Path(path).read_text())
    errors = validate_profile(d)
    if errors:
        raise ValueError("invalid scan-profile: " + "; ".join(errors))
    return ScanProfile.from_dict(d)


def save_profile(path: str | Path, profile: ScanProfile) -> None:
    """Write a scan-profile to disk as indented JSON.

    Args:
        path: Destination path.
        profile: Profile to serialize.
    """
    Path(path).write_text(json.dumps(profile.to_dict(), indent=2))
