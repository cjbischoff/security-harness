"""Tests for git diff scoping helpers."""

from sec_harness.diffscope import changed_files, head_sha


def test_changed_files_parses_name_only(monkeypatch):
    class R:
        stdout = "app.py\nsrc/db.py\n"
        returncode = 0

    def fake_run(cmd, capture_output, text, check):
        assert cmd[:3] == ["git", "diff", "--name-only"]
        return R()

    assert changed_files("sha1", "HEAD", runner=fake_run) == ["app.py", "src/db.py"]


def test_head_sha_strips(monkeypatch):
    class R:
        stdout = "abc1234\n"
        returncode = 0

    assert head_sha(runner=lambda *a, **k: R()) == "abc1234"
