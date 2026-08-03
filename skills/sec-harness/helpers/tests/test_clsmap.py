"""Tests for the unified CWE->attack-class mapping."""

from sec_harness.clsmap import (
    cls_from_cwe,
    cls_from_rule_id,
    cls_from_semgrep_meta,
    is_noise_class,
)


def test_codeql_resource_rules_route_to_resource_not_unknown():
    """High-severity CodeQL resource/DoS rules must route to `resource`, not
    fall to `unknown` and get demoted as noise (dogfood ISSUE-011)."""
    assert cls_from_rule_id("js/loop-bound-injection") == "resource"
    assert cls_from_rule_id("js/missing-rate-limiting") == "resource"
    assert cls_from_rule_id("py/polynomial-redos") == "resource"
    # and their CWE tags map too
    assert cls_from_cwe(["external/cwe/cwe-770"]) == "resource"
    assert cls_from_cwe(["CWE-400: Uncontrolled Resource Consumption"]) == "resource"
    assert cls_from_cwe(["external/cwe/cwe-834"]) == "resource"
    # resource is not a noise class -> not demoted
    assert not is_noise_class("resource")


def test_cls_from_cwe_formats():
    assert cls_from_cwe(["external/cwe/cwe-089"]) == "sqli"
    assert cls_from_cwe(["CWE-89: SQL Injection"]) == "sqli"          # semgrep-style
    assert cls_from_cwe(["external/cwe/cwe-117"]) == "log-injection"  # newly mapped
    assert cls_from_cwe(["external/cwe/cwe-312"]) == "clear-text-logging"
    assert cls_from_cwe(["security"]) == "unknown"


def test_cls_from_semgrep_meta():
    assert cls_from_semgrep_meta({"cls": "sqli"}) == "sqli"           # our own rules
    assert cls_from_semgrep_meta({"cwe": ["CWE-918: SSRF"]}) == "ssrf"
    assert cls_from_semgrep_meta({"cwe": "CWE-79: XSS"}) == "xss"
    assert cls_from_semgrep_meta({}) == "unknown"


def test_unmapped_cwe_is_security_other():
    assert cls_from_semgrep_meta({"cwe": ["CWE-1004: HttpOnly"]}) == "security-other"


def test_security_category_is_security_other():
    assert cls_from_semgrep_meta({"category": "security"}) == "security-other"


def test_lint_rule_stays_unknown():
    assert cls_from_semgrep_meta({"category": "best-practice"}) == "unknown"
    assert cls_from_semgrep_meta({}) == "unknown"


def test_cls_from_rule_id_routes_vendored_lang_rules():
    from sec_harness.clsmap import cls_from_rule_id
    assert cls_from_rule_id("rules.semgrep.php.lang.security.exec-use") == "cmdi"
    assert cls_from_rule_id("rules.semgrep.php.lang.security.backticks-use") == "cmdi"
    assert cls_from_rule_id("rules.semgrep.php.lang.security.mcrypt-use") == "crypto"
    assert cls_from_rule_id("rules.semgrep.php.lang.security.weak-crypto") == "crypto"
    assert cls_from_rule_id("rules.semgrep.php.lang.correctness.something") == ""
    assert cls_from_rule_id(None) == ""


def test_rule_id_rescues_security_other_and_unknown():
    # no cls, no cwe, category security -> would be security-other; rule_id rescues it
    assert cls_from_semgrep_meta({"category": "security"}, "x.security.exec-use") == "cmdi"
    # no metadata at all -> would be unknown; rule_id rescues it
    assert cls_from_semgrep_meta({}, "x.security.mcrypt-use") == "crypto"
    # unmapped cwe present, rule_id can still rescue
    assert cls_from_semgrep_meta({"cwe": ["CWE-1004: HttpOnly"]}, "x.weak-crypto") == "crypto"
    # explicit cls always wins over rule_id
    assert cls_from_semgrep_meta({"cls": "xss"}, "x.exec-use") == "xss"
    # a mapped cwe wins over rule_id
    assert cls_from_semgrep_meta({"cwe": ["CWE-89"]}, "x.exec-use") == "sqli"
    # non-security rule with no hint stays unknown
    assert cls_from_semgrep_meta({}, "x.correctness.foo") == "unknown"


def test_cls_from_rule_id_codeql_ids():
    from sec_harness.clsmap import cls_from_rule_id
    assert cls_from_rule_id("js/user-controlled-bypass") == "authn"
    assert cls_from_rule_id("js/incomplete-url-substring-sanitization") == "ssrf"
    assert cls_from_rule_id("js/incomplete-sanitization") == "xss"
    assert cls_from_rule_id("js/insecure-randomness") == "crypto"
    assert cls_from_rule_id("py/insecure-hash-algorithm-md5") == "crypto"
    assert cls_from_rule_id("py/clear-text-logging-sensitive-data") == "clear-text-logging"
    assert cls_from_rule_id("py/stack-trace-exposure") == "clear-text-logging"
    assert cls_from_rule_id("js/regex/missing-regexp-anchor") == ""  # unmapped, stays unknown


def test_noise_classes():
    from sec_harness.clsmap import NOISE_CLASSES, is_noise_class
    assert is_noise_class("log-injection") and is_noise_class("clear-text-logging")
    assert is_noise_class("unknown")
    assert not is_noise_class("sqli") and not is_noise_class("ssrf")
    assert "log-injection" in NOISE_CLASSES
