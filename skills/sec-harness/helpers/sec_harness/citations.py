"""Auto-attach ASVS 5.0 + CodeGuard citations to findings (F1 wiring).

Deterministic, not LLM-dependent: an investigate agent needn't remember ASVS ids —
this maps a finding's attack class to the relevant ASVS requirement ids + CodeGuard
rule, and stamps them on any finding that doesn't already carry citations. Run at
calibrate time so confirmed findings reach the report with a Compliance line.

Citations are advisory tags (rendered as compliance context), NOT tool receipts.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from sec_harness.asvs import AsvsCatalog, default_catalog_path
from sec_harness.models import Finding, FindingStatus
from sec_harness.workspace import Workspace, read_findings, write_findings

# attack-class -> ASVS 5.0 requirement ids (must exist in the shipped seed catalog).
CLASS_ASVS: dict[str, list[str]] = {
    "sqli": ["1.2.4"], "cmdi": ["1.2.5"], "ssrf": ["1.2.6"], "xss": ["1.3.1"],
    "dom-xss": ["1.3.1"], "ssti": ["1.3.1"], "deserialization": ["1.5.2"],
    "path-traversal": ["1.11.2"], "authn": ["6.1.1", "3.1.1"], "authz": ["4.1.1"],
    "jwt": ["3.5.3"], "crypto": ["6.2.1", "6.2.3"], "open-redirect": ["1.2.6"],
}

# attack-class -> CodeGuard rule id (file must exist under references/codeguard/).
CLASS_CODEGUARD: dict[str, str] = {
    "sqli": "codeguard-0-input-validation-injection",
    "cmdi": "codeguard-0-input-validation-injection",
    "deserialization": "codeguard-0-input-validation-injection",
    "ssti": "codeguard-0-input-validation-injection",
    "xxe": "codeguard-0-input-validation-injection",
    "request-smuggling": "codeguard-0-input-validation-injection",
    "crypto": "codeguard-0-cryptography",
    "xss": "codeguard-0-client-side-web-security",
    "dom-xss": "codeguard-0-client-side-web-security",
    "dom-clobbering": "codeguard-0-client-side-web-security",
    "cswsh": "codeguard-0-client-side-web-security",
    "prototype-pollution": "codeguard-0-client-side-web-security",
    "open-redirect": "codeguard-0-client-side-web-security",
    "path-traversal": "codeguard-0-file-handling-and-uploads",
    "authz": "codeguard-0-authorization-access-control",
    "authn": "codeguard-0-authorization-access-control",
    "jwt": "codeguard-0-authorization-access-control",
    "oauth-oidc": "codeguard-0-authorization-access-control",
    "saml": "codeguard-0-authorization-access-control",
    "excessive-agency": "codeguard-0-authorization-access-control",
    "ssrf": "codeguard-0-api-web-services",
    "webhook-verification": "codeguard-0-api-web-services",
    "cache-poisoning": "codeguard-0-api-web-services",
    "secrets": "codeguard-0-cryptography",
}


def citations_for(cls: str, catalog: AsvsCatalog | None = None) -> tuple[list[str], list[str]]:
    """Return (asvs_full_ids, codeguard_ids) for an attack class.

    Args:
        cls: The finding's attack class.
        catalog: Optional loaded ASVS catalog (to render ``full_id`` form and drop
            ids absent from the shipped catalog); defaults to the seed.

    Returns:
        ``([v5.0.0-x, ...], [codeguard-...])`` — empty lists when the class maps to none.
    """
    cat = catalog or AsvsCatalog.load(default_catalog_path())
    asvs = []
    for rid in CLASS_ASVS.get(cls, []):
        r = cat.get(rid)
        if r:
            asvs.append(r.full_id)
    cg = [CLASS_CODEGUARD[cls]] if cls in CLASS_CODEGUARD else []
    return asvs, cg


def attach(finding: Finding, catalog: AsvsCatalog | None = None) -> bool:
    """Stamp citations on a finding if it has none yet.

    Args:
        finding: The finding to annotate (mutated in place).
        catalog: Optional loaded ASVS catalog.

    Returns:
        True if anything was attached.
    """
    if finding.asvs_ids or finding.codeguard_ids:
        return False
    asvs, cg = citations_for(finding.cls, catalog)
    if not asvs and not cg:
        return False
    finding.asvs_ids = asvs
    finding.codeguard_ids = cg
    return True


_ANNOTATABLE = {FindingStatus.RAW, FindingStatus.CONFIRMED, FindingStatus.FIXED}


def annotate_findings(ws: Workspace) -> int:
    """Attach citations to all raw/confirmed/fixed findings lacking them.

    Args:
        ws: Workspace whose findings are annotated in place.

    Returns:
        The number of findings updated.
    """
    catalog = AsvsCatalog.load(default_catalog_path())
    findings = read_findings(ws)
    changed = 0
    for f in findings:
        if f.status in _ANNOTATABLE and attach(f, catalog):
            changed += 1
    if changed:
        write_findings(ws, findings)
    return changed


def main(argv: list[str] | None = None) -> int:
    """CLI: attach ASVS/CodeGuard citations to a workspace's findings."""
    p = argparse.ArgumentParser(prog="sec-harness-citations")
    p.add_argument("--workspace", required=True)
    args = p.parse_args(argv)
    n = annotate_findings(Workspace(Path(args.workspace)))
    print(f"annotated {n} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
