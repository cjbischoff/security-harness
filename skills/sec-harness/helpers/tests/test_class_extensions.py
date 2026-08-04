from pathlib import Path

CLASSES_DIR = Path(__file__).resolve().parents[1].parent / "agents" / "classes"
REQUIRED = {"authz", "authn", "crypto", "injection", "config", "resource",
            "ssrf", "prompt-injection", "excessive-agency", "context-bleed",
            "business-logic"}


def test_every_required_class_has_extension_with_proof_tuple():
    missing = [c for c in REQUIRED if not (CLASSES_DIR / f"{c}.md").exists()]
    assert not missing, f"missing class extensions: {missing}"
    for c in REQUIRED:
        text = (CLASSES_DIR / f"{c}.md").read_text()
        assert "## Proof tuple" in text, f"{c}.md lacks a Proof tuple section"
