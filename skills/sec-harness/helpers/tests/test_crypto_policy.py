"""Tests for machine-checked crypto policy CBC/AEAD and KDF checks."""

from sec_harness.crypto_policy import check


def test_cbc_without_aead_is_denied():
    assert check("aes-256-cbc")["ok"] is False


def test_gcm_still_ok():
    assert check("aes-256-gcm")["ok"] is True


def test_bare_hash_as_kdf_is_denied():
    assert check("sha256", params={"kdf_context": True})["ok"] is False
