#!/usr/bin/env python3
"""Generate canonical byte-target goldens from the real Python sec_harness contract.

This is the parity oracle for the Go port: it instantiates a fixed set of
``Finding``/``CampaignState`` values against the authoritative Python
``sec_harness.models`` and writes each object's ``json.dumps(obj.to_dict(),
indent=2)`` (no trailing newline) into ``go/internal/model/testdata/``. The Go
``TestParity`` / ``TestCampaignParity`` tests marshal the equivalent Go objects
and assert byte-equality against these files. Stdlib-only — a plain ``python3``
runs it (the core has zero dependencies).

Run: ``python3 go/bench/gen_golden.py``
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[2]
_HELPERS = _REPO_ROOT / "skills/sec-harness/helpers"
_TESTDATA = _HERE.parents[1] / "internal/model/testdata"
_RAW_FIXTURE = _HELPERS / "fixtures/golden_raw_finding.json"

sys.path.insert(0, str(_HELPERS))

from sec_harness.models import (  # noqa: E402
    CampaignState,
    Finding,
    FindingStatus,
    Severity,
)


def _write(name: str, obj_dict: dict) -> None:
    """Write ``json.dumps(obj_dict, indent=2)`` with no trailing newline."""
    path = _TESTDATA / f"{name}.golden.json"
    path.write_text(json.dumps(obj_dict, indent=2))
    print(f"wrote {path.relative_to(_REPO_ROOT)}")


def main() -> None:
    """Emit the five goldens plus a copy of the raw tolerant-decode input."""
    _TESTDATA.mkdir(parents=True, exist_ok=True)

    # (1) minimal — required fields only (matches the RESEARCH empty-Finding target).
    finding_min = Finding(
        id="F-0001",
        rule_id="r",
        cls="sqli",
        status=FindingStatus.RAW,
        severity=Severity.HIGH,
        file="app.py",
        line=18,
        message="m",
    )
    _write("finding_min", finding_min.to_dict())

    # (2) full — every optional scalar and list populated. Evidence carries HTML
    # metacharacters (< > &) and a non-ASCII rune to exercise SetEscapeHTML(false)
    # and the \uXXXX ensure_ascii pass.
    finding_full = Finding(
        id="F-0100",
        rule_id="python-sqli-string-format",
        cls="sqli",
        status=FindingStatus.CONFIRMED,
        severity=Severity.CRITICAL,
        file="app.py",
        line=18,
        message='tainted id flows into SQL where a < b && c > d — café',
        dataflow=["request.args.get('id') @ app.py:15", "-> cur.execute(...) @ app.py:18"],
        risk_score=8,
        verification="verified-static",
        patch_diff="--- a/app.py\n+++ b/app.py\n",
        discovery_sha="abc123",
        duplicate_of="F-0000",
        history=[{"pass": 1, "event": "investigated:confirmed"}],
        fingerprint="afbc8b946dbd",
        priority="P1",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence='cur.execute("SELECT * FROM users WHERE id = \'%s\'" % uid) <&>',
        evidence_sources=["semgrep:python.sqli", "llm-claimed:reachable"],
        asvs_ids=["V5.3.4"],
        codeguard_ids=["CG-SQLI-001"],
        completeness_tier="FULL",
        runtime_disposition="static-settled",
        preconditions=["authenticated session"],
        judge_verdict="uphold",
    )
    _write("finding_full", finding_full.to_dict())

    # (3) nested — populated reachability + runtime_test, and one history entry of
    # every shape observed in the Python core (grep 'history.append(' across
    # sec_harness/: verify.py, dedupe.py, campaign.py, factcheck.py, calibrate.py,
    # context.py, plus the {pass,event} investigate shape).
    finding_nested = Finding(
        id="F-0200",
        rule_id="r2",
        cls="ssrf",
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        file="fetch.py",
        line=42,
        message="server-side request to attacker-controlled host",
        history=[
            {"pass": 1, "event": "investigated:confirmed"},
            {"event": "verify:fixed"},
            {"event": "salvaged", "reason": "agent crashed"},
            {"event": "factcheck:corrected", "field": "severity", "value": "medium"},
            {"event": "calibrate:severity-inflated", "claimed": "high", "derived": 6, "delta": 2},
            {"event": "context:control-verification", "verify_status": "not-enforced", "source_doc": "SECURITY.md"},
        ],
        runtime_disposition="needs-runtime",
        runtime_test={
            "objective": "prove outbound fetch reaches an internal host",
            "preconditions": ["authenticated"],
            "payloads": ["http://169.254.169.254/latest/meta-data/"],
            "expected_signal": "metadata response body echoed",
            "telemetry": "egress log to 169.254.169.254",
        },
        preconditions=["network egress allowed"],
        reachability={
            "reachable": True,
            "blocker": None,
            "chain": ["fetch.py:40", "fetch.py:42"],
        },
    )
    _write("finding_nested", finding_nested.to_dict())

    # (4) campaign — insertion-ordered multi-key stages (recon -> architecture ->
    # threat-model -> prefilter) proves non-alphabetical key order; empty budget.
    campaign = CampaignState(
        pass_number=1,
        active_sha="deadbeef",
        stages={
            "recon": "done",
            "architecture": "done",
            "threat-model": "done",
            "prefilter": "done",
        },
        budget={},
    )
    _write("campaign", campaign.to_dict())

    # (5) partial_roundtrip — Python's own tolerant-decode-then-canonical-serialize
    # of the partial/extra-key raw fixture. This is the byte-target the Go
    # tolerant-decode test compares against.
    raw = json.loads(_RAW_FIXTURE.read_text())
    _write("partial_roundtrip", Finding.from_dict(raw).to_dict())

    # Copy the raw input beside the goldens so the Go test is self-contained
    # (reads testdata/ only, never reaches outside the module).
    dest = _TESTDATA / "finding_raw_input.json"
    shutil.copyfile(_RAW_FIXTURE, dest)
    print(f"copied {dest.relative_to(_REPO_ROOT)}")


if __name__ == "__main__":
    main()
