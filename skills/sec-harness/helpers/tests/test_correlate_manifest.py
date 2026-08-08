from __future__ import annotations

import json
from pathlib import Path

import pytest

from sec_harness.correlate.manifest import Member, load_manifest, validate_manifest


def _doc(**kw) -> dict:
    d = {"product": "p", "members": [
        {"slug": "a-1", "repo_root": "/r/a", "scan_scope": ".", "role": "rbac-source"},
        {"slug": "go-1", "repo_root": "/r/go", "scan_scope": "internal/svc", "role": "service-enforcer"},
    ]}
    d.update(kw)
    return d


def test_member_key_disambiguates_monorepo_subdirs():
    m1 = Member(slug="go-1", repo_root="/r/go", scan_scope="internal/svcA", role="service-enforcer")
    m2 = Member(slug="go-1", repo_root="/r/go", scan_scope="internal/svcB", role="service-enforcer")
    assert m1.member_key == "go-1#internal/svcA"
    assert m1.member_key != m2.member_key  # shared slug, distinct member key


def test_load_valid(tmp_path: Path):
    p = tmp_path / "product.json"; p.write_text(json.dumps(_doc()))
    man = load_manifest(p)
    assert man.product == "p"
    assert [m.role for m in man.members] == ["rbac-source", "service-enforcer"]


def test_validate_rejects_bad_role():
    errs = validate_manifest(_doc(members=[{"slug": "a", "repo_root": "/r", "scan_scope": ".",
                                            "role": "bogus"}]))
    assert any("role" in e for e in errs)


def test_validate_requires_members():
    assert any("members" in e for e in validate_manifest({"product": "p", "members": []}))


def test_load_invalid_raises(tmp_path: Path):
    p = tmp_path / "bad.json"; p.write_text(json.dumps({"product": "p", "members": [{"slug": "a"}]}))
    with pytest.raises(ValueError):
        load_manifest(p)
