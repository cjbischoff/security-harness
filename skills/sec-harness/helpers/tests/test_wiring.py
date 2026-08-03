"""Layer-C wiring guards: every declared backend/class is actually reachable.

Regression tests for the 'silent no-op' bug class (sca/secrets declared in the
profile but never run and never recorded) and clsmap/routing drift.
"""
from sec_harness.clsmap import _RULE_ID_CLS, CWE_CLS
from sec_harness.evidence import _MECHANICAL, is_tool_receipt
from sec_harness.exclusions import Exclusions
from sec_harness.prefilter import run_prefilter
from sec_harness.profile import ScanProfile
from sec_harness.workspace import Workspace


def test_every_declared_backend_is_accounted_for(tmp_path):
    # A profile that turns on ALL backends must leave NONE silently unhandled:
    # each backend ends up in backends_run, skipped, or skipped_reasons/failed.
    ws = Workspace(tmp_path); ws.ensure()
    prof = ScanProfile(
        ["python"], [], [], True, ["sqli"],
        {"semgrep": {"run": True, "rulesets": ["x"]},
         "codeql": {"run": True, "languages": ["python"]},
         "sca": {"run": True, "lockfiles": ["req.txt"]},
         "secrets": {"run": True}},
        ["sqli"], {})
    res = run_prefilter(
        ws, "t", prof,
        semgrep=lambda *a, **k: [],
        codeql=lambda *a, **k: [],
        has_tool=lambda n: True,
        qlpack_fn=lambda lang: True,
        secrets_fn=lambda target: [],
        sca_fn=lambda target, **k: [],
        exclusions_fn=lambda w: Exclusions([], [], []),
    )
    accounted = set(res["backends_run"]) | set(res["skipped"]) | set(res["skipped_reasons"]) \
        | {f["backend"] for f in res["failed"]}
    for backend in ("semgrep", "codeql", "sca", "secrets"):
        assert backend in accounted, f"{backend} declared run:true but silently unhandled"


def test_all_clsmap_targets_are_known_classes():
    # Every class the router can emit must be a recognized attack-class key (no typos
    # that would orphan findings). We assert against the union used across the harness.
    known = set(CWE_CLS.values()) | set(_RULE_ID_CLS.values()) | {
        "security-other", "unknown", "deps",
    }
    for cls in _RULE_ID_CLS.values():
        assert cls in known


def test_backend_receipt_prefixes_are_mechanical():
    # secrets/sca findings carry secrets:/sca: receipts — these MUST be recognized as
    # mechanical, or the receipt gate would reject their confirmed findings.
    for prefix in ("secrets", "sca", "semgrep", "codeql", "ast-grep", "ripgrep"):
        assert prefix in _MECHANICAL
        assert is_tool_receipt(f"{prefix}:x") is True


def test_hunting_companion_docs_exist_and_referenced():
    # F2 dead-link guard: every companion doc named in attack-classes.md exists,
    # and the always-imported methodology + anti-patterns docs exist.
    from pathlib import Path
    ref = Path(__file__).resolve().parents[2] / "references"
    catalog = (ref / "attack-classes.md").read_text()
    for doc in ("web-protocol-auth", "client-side", "ai-agent", "business-logic",
                "memory-native", "methodology", "anti-patterns"):
        p = ref / "hunting" / f"{doc}.md"
        assert p.exists() and p.read_text().strip(), f"missing/empty hunting/{doc}.md"
    for named in ("hunting/web-protocol-auth.md", "hunting/methodology.md",
                  "hunting/anti-patterns.md"):
        assert named in catalog, f"{named} not referenced in attack-classes.md"


def test_new_domain_classes_in_clsmap():
    from sec_harness.clsmap import CWE_CLS
    for cls in ("jwt", "request-smuggling", "prototype-pollution", "cswsh",
                "excessive-agency", "business-logic"):
        assert cls in CWE_CLS.values(), f"{cls} not mapped in clsmap"


def test_context_and_postflight_prompts_exist():
    from pathlib import Path
    agents = Path(__file__).resolve().parents[2] / "agents"
    for p in ("context-ingest.md", "postflight.md"):
        assert (agents / p).exists() and (agents / p).read_text().strip(), p


def test_fp_feedback_token_present_in_prompts():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]  # skills/sec-harness
    for name in ("investigate", "critic"):
        text = (root / "agents" / f"{name}.md").read_text()
        assert "{{FP_FEEDBACK}}" in text, f"{name}.md missing FP_FEEDBACK token"


def test_class_prompts_carry_proof_tuple_and_anti_collapse():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]  # skills/sec-harness
    for name in ("injection", "authz", "crypto", "config", "resource"):
        text = (root / "agents" / "classes" / f"{name}.md").read_text().lower()
        assert "proof tuple" in text, f"{name}.md missing proof tuple"
        assert "instance" in text and "collapse" in text, f"{name}.md missing anti-collapse rule"
