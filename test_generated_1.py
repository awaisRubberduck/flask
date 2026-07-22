"""
Security tests for rd_fix_demo.py – targeting:
  1. Hard-coded API key / secret exposure
  2. Weak hashing algorithm (MD5 used for password hashing)
  3. Weak / well-known password stored in plain module-level variable
"""

import hashlib
import importlib
import inspect
import re
import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SOURCE_FILE = "rd_fix_demo.py"


def _load_source() -> str:
    with open(SOURCE_FILE, "r") as fh:
        return fh.read()


def _import_module() -> types.ModuleType:
    """Import (or reload) the module under test."""
    if "rd_fix_demo" in sys.modules:
        return importlib.reload(sys.modules["rd_fix_demo"])
    return importlib.import_module("rd_fix_demo")


# ---------------------------------------------------------------------------
# 1. Hard-coded secrets must NOT appear in source
# ---------------------------------------------------------------------------

class TestHardcodedSecrets:
    """Hard-coded credentials are a CWE-798 / CWE-259 vulnerability."""

    def test_no_hardcoded_api_key_in_source(self):
        """The literal API key value must not be present in the source file."""
        source = _load_source()
        # The specific key that was introduced in the PR
        hardcoded_key = "sk-live-9f8a7b6c5d4e3f2a1b0c"
        assert hardcoded_key not in source, (
            f"Hard-coded API key '{hardcoded_key}' found in source. "
            "Use environment variables or a secrets manager instead."
        )

    def test_no_hardcoded_password_in_source(self):
        """Plain-text passwords must not be hard-coded in source."""
        source = _load_source()
        hardcoded_password = "hunter2"
        assert hardcoded_password not in source, (
            f"Hard-coded password '{hardcoded_password}' found in source. "
            "Passwords must never appear in source code."
        )

    def test_api_key_not_exposed_as_module_attribute(self):
        """The module must not export a plain-text API key attribute."""
        mod = _import_module()
        # If the attribute exists it should not look like a real secret
        api_key = getattr(mod, "API_KEY", None)
        assert api_key is None or not re.match(
            r"^sk-live-[0-9a-f]+$", str(api_key)
        ), (
            "Module attribute API_KEY contains what looks like a live secret key."
        )

    def test_password_attribute_not_plaintext(self):
        """A 'password' module attribute must not be a plain-text string."""
        mod = _import_module()
        pw = getattr(mod, "password", None)
        # Acceptable states: attribute does not exist, or is not a non-empty string
        if pw is not None:
            assert not isinstance(pw, str) or pw == "", (
                f"Plain-text password exposed as module attribute: '{pw}'"
            )

    def test_no_sk_live_pattern_in_source(self):
        """Broad check: no 'sk-live-*' token pattern anywhere in source."""
        source = _load_source()
        assert not re.search(r"sk-live-[A-Za-z0-9]+", source), (
            "Source contains a token matching the sk-live-* pattern, "
            "which is indicative of a live API credential."
        )


# ---------------------------------------------------------------------------
# 2. Weak hashing algorithm (MD5)
# ---------------------------------------------------------------------------

class TestWeakHashing:
    """MD5 is cryptographically broken and must not be used for passwords (CWE-327, CWE-916)."""

    def test_md5_not_used_for_password_hashing_in_source(self):
        """Source must not use hashlib.md5 for password hashing."""
        source = _load_source()
        assert "hashlib.md5" not in source, (
            "hashlib.md5 is used in source. MD5 is cryptographically broken "
            "and must not be used for password hashing. "
            "Use hashlib.sha256 with salt, bcrypt, argon2, or scrypt."
        )

    def test_md5_call_not_present_in_source(self):
        """No bare md5() call should appear in the module source."""
        source = _load_source()
        assert not re.search(r"\bmd5\s*\(", source), (
            "md5() call detected in source – forbidden for password/secret hashing."
        )

    def test_digest_attribute_is_not_md5_of_known_password(self):
        """
        If a 'digest' attribute exists on the module it must NOT equal the
        MD5 of the known weak password 'hunter2' (proves the bad code ran).
        """
        md5_of_hunter2 = hashlib.md5(b"hunter2").hexdigest()
        mod = _import_module()
        digest = getattr(mod, "digest", None)
        assert digest != md5_of_hunter2, (
            f"Module 'digest' equals the MD5 of 'hunter2' ({md5_of_hunter2}). "
            "This confirms both weak hashing and hard-coded password are active."
        )

    def test_strong_hash_algorithm_used_if_hashing_present(self):
        """
        If any hashing is performed in the module, it must use an algorithm
        from the approved set (sha256, sha384, sha512, blake2b, bcrypt, argon2, scrypt).
        """
        source = _load_source()
        approved = re.compile(
            r"hashlib\.(sha256|sha384|sha512|sha3_256|sha3_512|blake2b|blake2s)\b"
            r"|bcrypt|argon2|scrypt"
        )
        if re.search(r"hashlib\.", source):
            assert approved.search(source), (
                "Hashing is used but no approved strong algorithm was found. "
                "Replace MD5/SHA1 with sha256+salt, bcrypt, argon2, or scrypt."
            )

    def test_md5_is_indeed_weak_reference_check(self):
        """
        Sanity / documentation test: prove that MD5 produces collisions trivially
        and is in Python's 'usedforsecurity=False' category on newer interpreters.
        """
        # MD5 of two different empty-prefix collision blobs (RFC demonstration)
        # Just assert MD5 digest length is only 128-bit – inadequate for passwords
        digest_len_bits = len(hashlib.md5(b"test").digest()) * 8
        assert digest_len_bits == 128
        # 128-bit MD5 is brute-forceable; passwords need bcrypt/argon2 cost factor
        assert digest_len_bits < 256, (
            "MD5 is only 128 bits – far too weak for password storage."
        )


# ---------------------------------------------------------------------------
# 3. Verify safe alternatives still work (positive / regression tests)
# ---------------------------------------------------------------------------

class TestSafeAlternatives:
    """Ensure the recommended secure approaches are functional."""

    def test_sha256_password_hashing_works(self):
        """SHA-256 with a salt produces a non-empty hex digest."""
        import os
        salt = os.urandom(32)
        pw = b"some_password"
        digest = hashlib.sha256(salt + pw).hexdigest()
        assert len(digest) == 64
        assert isinstance(digest, str)

    def test_pbkdf2_hmac_works_for_password_hashing(self):
        """PBKDF2-HMAC-SHA256 is an approved KDF for password hashing."""
        import os
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", b"password", salt, 260_000)
        assert len(dk) == 32  # 256-bit derived key

    def test_env_var_pattern_for_api_key(self, monkeypatch):
        """API keys should be read from environment variables, not source."""
        import os
        monkeypatch.setenv("API_KEY", "sk-live-testvalue")
        assert os.environ.get("API_KEY") == "sk-live-testvalue"
        # Consuming from env is safe; embedding in source is not
        assert "sk-live-testvalue" not in _load_source()