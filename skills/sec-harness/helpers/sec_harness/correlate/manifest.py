"""Product manifest: the explicit set of member repos (with roles) to correlate."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROLES = ("rbac-source", "service-enforcer", "infra")


@dataclass
class Member:
    """One repo (or monorepo sub-service) participating in a product correlation.

    Attributes:
        slug: The member's ``repo_slug`` (Plan 1). May be shared by two monorepo sub-services.
        repo_root: Absolute git top-level of the member.
        scan_scope: Path relative to ``repo_root`` scanned ("." for a whole repo).
        role: One of :data:`ROLES` — drives the contract-consistency lattice (B-Plan 2).
    """

    slug: str
    repo_root: str
    scan_scope: str
    role: str

    @property
    def member_key(self) -> str:
        """Unique key ``<slug>#<scan_scope>`` (disambiguates monorepo sub-services)."""
        return f"{self.slug}#{self.scan_scope}"


@dataclass
class Manifest:
    """A product's correlation membership.

    Attributes:
        product: The product identifier.
        members: List of member repos participating in the correlation.
    """

    product: str
    members: list[Member]


def validate_manifest(d: dict) -> list[str]:
    """Validate a manifest dict; empty list == valid.

    Args:
        d: Parsed manifest dict.

    Returns:
        Human-readable error strings.
    """
    errs: list[str] = []
    if not isinstance(d.get("product"), str) or not d.get("product"):
        errs.append("manifest.product must be a non-empty string")
    members = d.get("members")
    if not isinstance(members, list) or not members:
        errs.append("manifest.members must be a non-empty list")
        members = []
    for i, m in enumerate(members):
        if not isinstance(m, dict):
            errs.append(f"members[{i}] must be an object")
            continue
        for key in ("slug", "repo_root", "scan_scope", "role"):
            if not isinstance(m.get(key), str) or not m.get(key):
                errs.append(f"members[{i}].{key} must be a non-empty string")
        if m.get("role") not in ROLES:
            errs.append(f"members[{i}].role must be one of {list(ROLES)}")
    return errs


def load_manifest(path: str | Path) -> Manifest:
    """Load + validate a product manifest JSON file.

    Args:
        path: Path to ``product.json``.

    Returns:
        The parsed :class:`Manifest`.

    Raises:
        ValueError: If the manifest fails validation.
    """
    d = json.loads(Path(path).read_text())
    errs = validate_manifest(d)
    if errs:
        raise ValueError("invalid manifest: " + "; ".join(errs))
    return Manifest(product=d["product"],
                    members=[Member(slug=m["slug"], repo_root=m["repo_root"],
                                    scan_scope=m["scan_scope"], role=m["role"])
                             for m in d["members"]])
