"""Tests for the password-hashing scheme (server.auth).

Covers the salted PBKDF2-HMAC-SHA256 format, salt uniqueness, and the
transparent upgrade path from the legacy unsalted SHA-256 hashes.
"""
import hashlib

from server.auth import hash_password, verify_password


class TestSaltedHashing:
    def test_correct_password_verifies(self):
        stored = hash_password("S3cure!Pass")
        ok, needs_upgrade = verify_password("S3cure!Pass", stored)
        assert ok is True
        assert needs_upgrade is False

    def test_wrong_password_rejected(self):
        stored = hash_password("S3cure!Pass")
        ok, _ = verify_password("wrong-password", stored)
        assert ok is False

    def test_same_password_produces_different_hashes(self):
        """Random salt: identical passwords must never share a hash."""
        assert hash_password("repeat") != hash_password("repeat")

    def test_hash_format_is_self_describing(self):
        stored = hash_password("x")
        algo, iterations, salt_hex, hash_hex = stored.split("$", 3)
        assert algo == "pbkdf2_sha256"
        assert int(iterations) >= 100_000
        assert len(bytes.fromhex(salt_hex)) == 16
        assert len(bytes.fromhex(hash_hex)) == 32  # sha256 digest

    def test_empty_stored_hash_rejected(self):
        ok, needs_upgrade = verify_password("anything", "")
        assert (ok, needs_upgrade) == (False, False)

    def test_malformed_stored_hash_rejected_not_crashed(self):
        ok, _ = verify_password("anything", "pbkdf2_sha256$not$valid$hex")
        assert ok is False


class TestLegacyUpgradePath:
    def test_legacy_sha256_verifies_and_flags_upgrade(self):
        legacy = hashlib.sha256(b"OldPassword1").hexdigest()
        ok, needs_upgrade = verify_password("OldPassword1", legacy)
        assert ok is True
        assert needs_upgrade is True  # caller should re-hash with hash_password()

    def test_legacy_wrong_password_rejected(self):
        legacy = hashlib.sha256(b"OldPassword1").hexdigest()
        ok, _ = verify_password("guess", legacy)
        assert ok is False
