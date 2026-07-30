"""Noise-floor exclusions: drop rules/paths/classes that only yield FPs.

Exclusions are explicit + evidence-backed (a `reason` in the file). The
prefilter applies them and logs the drop count — suppression is never silent.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field

from sec_harness.models import Finding
from sec_harness.workspace import Workspace


@dataclass
class Exclusions:
    """A set of noise-floor exclusion rules.

    Attributes:
        rule_ids: Detector rule ids to drop.
        paths: Glob patterns; a finding whose file matches any is dropped.
        classes: Attack-class keys to drop wholesale.
    """

    rule_ids: set[str] = field(default_factory=set)
    paths: list[str] = field(default_factory=list)
    classes: set[str] = field(default_factory=set)


def load_exclusions(ws: Workspace) -> Exclusions:
    """Load exclusions from ``kb/exclusions.json`` (empty if absent).

    Args:
        ws: Workspace to read from.

    Returns:
        The parsed :class:`Exclusions` (unknown keys like ``reason`` ignored).
    """
    path = ws.kb / "exclusions.json"
    if not path.exists():
        return Exclusions()
    d = json.loads(path.read_text())
    return Exclusions(
        rule_ids=set(d.get("rule_ids", [])),
        paths=list(d.get("paths", [])),
        classes=set(d.get("classes", [])),
    )


def apply_exclusions(
    findings: list[Finding], ex: Exclusions
) -> tuple[list[Finding], list[Finding]]:
    """Partition findings into (kept, dropped) by the exclusion rules.

    Args:
        findings: Candidate findings.
        ex: The exclusions to apply.

    Returns:
        ``(kept, dropped)``. A finding drops if its rule_id, cls, or a
        path-glob match hits.
    """
    kept: list[Finding] = []
    dropped: list[Finding] = []
    for f in findings:
        excluded = (
            f.rule_id in ex.rule_ids
            or f.cls in ex.classes
            or any(fnmatch.fnmatch(f.file, pat) for pat in ex.paths)
        )
        (dropped if excluded else kept).append(f)
    return kept, dropped
