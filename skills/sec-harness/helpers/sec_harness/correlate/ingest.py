"""Read-only ingest of member sidecars into cross-repo-tagged findings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sec_harness.correlate.manifest import Manifest, Member
from sec_harness.models import Finding
from sec_harness.repo_memory import RepoMemory
from sec_harness.workspace import Workspace, read_findings


@dataclass
class IngestedFinding:
    """A member finding tagged with its cross-repo identity.

    Attributes:
        member_key: The member's unique key (``<slug>#<scan_scope>``).
        role: The member's role in the correlation.
        cross_repo_id: Globally unique finding id (``member_key:file:line:rule_id``).
        finding: The Finding object.
    """

    member_key: str
    role: str
    cross_repo_id: str
    finding: Finding


def member_workspace(member: Member) -> Workspace:
    """Resolve a member's sidecar Workspace (read-only use).

    The sidecar lives at ``<repo_root>/.sec-harness/<slug>/`` — the same location a scan wrote it.

    Args:
        member: The manifest member.

    Returns:
        The member's campaign :class:`Workspace`.
    """
    return RepoMemory(root=Path(member.repo_root) / ".sec-harness" / member.slug).workspace


def ingest(manifest: Manifest) -> list[IngestedFinding]:
    """Read every member's findings read-only, tagged with a cross-repo id.

    Args:
        manifest: The product manifest.

    Returns:
        All members' findings as :class:`IngestedFinding` (empty if a member has none). Opens no
        member file for write.
    """
    out: list[IngestedFinding] = []
    for member in manifest.members:
        ws = member_workspace(member)
        for f in read_findings(ws):
            cid = f"{member.member_key}:{f.file}:{f.line}:{f.rule_id}"
            out.append(
                IngestedFinding(member_key=member.member_key, role=member.role,
                                cross_repo_id=cid, finding=f)
            )
    return out


def member_coverage(manifest: Manifest) -> dict[str, dict]:
    """Load each member's coverage-ledger (read-only), keyed by member_key.

    Args:
        manifest: The product manifest.

    Returns:
        ``{member_key: <coverage-ledger dict>}``; a member with no ``kb/coverage-ledger.json``
        maps to ``{}``. Opens no member file for write.
    """
    out: dict[str, dict] = {}
    for member in manifest.members:
        p = member_workspace(member).kb / "coverage-ledger.json"
        out[member.member_key] = json.loads(p.read_text()) if p.is_file() else {}
    return out
