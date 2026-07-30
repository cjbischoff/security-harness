"""Shared pytest fixtures for sec_harness tests."""

from pathlib import Path

import pytest


@pytest.fixture
def fixture_repo() -> Path:
    """Return the path to the bundled vulnerable fixture repository.

    Returns:
        Path: Absolute path to ``fixtures/vulnerable_repo``.
    """
    return (Path(__file__).parent.parent / "fixtures" / "vulnerable_repo").resolve()
