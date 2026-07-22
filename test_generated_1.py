"""
Security tests for rd_fix_demo.py – targeting:
  1. Hard-coded API key / secret exposure (CWE-798)
  2. Hard-coded plain-text password (CWE-259)
  3. Weak hashing algorithm – MD5 used for password hashing (CWE-327, CWE-916)
"""

import hashlib
import importlib
import os
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
    """Import (or reload) the module under test so changes are picked up."""
    if "rd_fix_demo" in sys.modules:
        return importlib.reload(sys.modules["rd_fix_demo"])
    return importlib.import_module("rd_fix_demo")


# ---------------------------------------------------------------------------
# 1. Hard-coded API key  (CWE-798)
# ---------------------------------------------------------------------------

class TestHardcodedApiKey:
    """The literal API key introduced in the PR must not live in source."""

    KNOWN_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c"

    def test_exact_api_key_not_in_source(self):
        source = _load_source()
        assert self.KNOWN_KEY not in source, (
            f"Hard-coded API key '{self.KNOWN_KEY}' found in source. "
            "Store secrets in environment variables or a secrets manager."
        )

    def test_sk_live_pattern_absent_from_source(self):
        """Catch any variant of the sk-live-* credential pattern."""
        source = _load_source()
        assert not re.search(r"sk-live-[A-Za-z0-9]+", source), (
            "Source contains a token matching sk-live-* – looks like a live API credential."
        )

    def test_api_key_module_attribute_is_not_live_secret(self):
        """If API_KEY is exported it must not contain the live key value."""
        mod = _import_module()
        api_key = getattr(mod, "API_KEY", None)
        if api_key is not None:
            assert api_key != self.KNOWN_KEY, (
                "Module attribute API_KEY holds the hard-coded live secret."
            )
            assert not re.match(r"^sk-live-[0-9a-f]+$", str(api_key)), (
                "Module attribute API_KEY matches the sk-live-* secret pattern."
            )

    def test_api_key_not_present_as_module_attribute_at_all(self):
        """Ideal state: no API_KEY attribute on the module (use env vars)."""
        mod = _import_module()
        assert not hasattr(mod, "API_KEY"), (
            "Module exposes API_KEY as a top-level attribute. "
            "Use os.environ.get('API_KEY') at call-site instead."
        )


# ---------------------------------------------------------------------------
# 2. Hard-coded plain-text password  (CWE-259)
# ---------------------------------------------------------------------------

class TestHardcodedPassword:
    """The literal password 'hunter2' introduced in the PR must not live in source."""

    KNOWN_PASSWORD = "hunter2"

    def test_exact_password_not_in_source(self):
        source = _load_source()
        assert self.KNOWN_PASSWORD not in source, (
            f"Hard-coded password '{self.KNOWN_PASSWORD}' found in source. "
            "Passwords must never appear in source code."
        )

    def test_password_module_attribute_absent(self):
        """The module must not export a plain-text 'password' attribute."""
        mod = _import_module()
        assert not hasattr(mod, "password"), (
            "Module exposes a top-level 'password' attribute – this is a secret leak."
        )

    def test_password_attribute_not_plaintext_string(self):
        """If a 'password' attribute somehow exists it must not be a non-empty string."""
        mod = _import_module()
        pw = getattr(mod, "password", None)
        if pw is not None:
            assert not (isinstance(pw, str) and pw != ""), (
                f"Plain-text password exposed as module attribute: '{pw}'"
            )

    def test_known_password_value_not_in_any_module_string_attribute(self):
        """
        Walk all string attributes of the module; none should equal or
        contain the known hard-coded password.
        """
        mod = _import_module()
        for name in dir(mod):
            if name.startswith("__"):
                continue
            val = getattr(mod, name, None)
            if isinstance(val, str):
                assert self.KNOWN_PASSWORD not in val, (
                    f"Module attribute '{name}' contains the hard-coded password."
                )


# ---------------------------------------------------------------------------
# 3. Weak hashing algorithm – MD5  (CWE-327 / CWE-916)
# ---------------------------------------------------------------------------

class TestWeakMd5Hashing:
    """MD5 is cryptographically broken and must not be used for passwords."""

    def test_hashlib_md5_not_in_source(self):
        source = _load_source()
        assert "hashlib.md5" not in source, (
            "hashlib.md5 is present in source. MD5 is broken; use bcrypt, "
            "argon2id, or hashlib.scrypt/pbkdf2_hmac with sha-256."
        )

    def test_md5_call_pattern_absent_from_source(self):
        """Catch any bare md5( call regardless of import style."""
        source = _load_source()
        assert not re.search(r"\bmd5\s*\(", source), (
            "md5() call detected in source – forbidden for password/secret hashing."
        )

    def test_digest_attribute_is_not_md5_of_known_password(self):
        """
        The module's 'digest' attribute must not equal the MD5 of 'hunter2'.
        This would confirm both weak hashing and hard-coded password are live.
        """
        md5_of_hunter2 = hashlib.md5(b"hunter2").hexdigest()  # noqa: S324
        mod = _import_module()
        digest = getattr(mod, "digest", None)
        assert digest != md5_of_hunter2, (
            f"Module 'digest' == MD5('hunter2') = {md5_of_hunter2}. "
            "Both a weak algorithm and a hard-coded password are confirmed active."
        )

    def test_digest_attribute_does_not_exist_or_uses_strong_algorithm(self):
        """
        If a 'digest' attribute is present it should be produced by a strong
        algorithm (sha-256 output is 64 hex chars; MD5 output is 32 hex chars).
        """
        mod = _import_module()
        digest = getattr(mod, "digest", None)
        if digest is not None and isinstance(digest, str):
            # MD5 hex digest is exactly 32 characters
            assert len(digest) != 32, (
                f"Module 'digest' is 32 hex characters – consistent with MD5 output."
            )

    def test_no_strong_hash_algorithm_replaces_md5_yet(self):
        """
        Verify the source does NOT already use an approved KDF, confirming
        the bad code is still active (test will fail once properly fixed –
        which is the intended signal).
        """
        source = _load_source()
        # If the code is fixed this assertion will fail and remind us to
        # update/remove these security tests.
        approved = re.compile(
            r"hashlib\.(sha256|sha384|sha512|sha3_256|sha3_512|blake2b|blake2s|pbkdf2_hmac|scrypt)\b"
            r"|bcrypt|argon2"
        )
        if re.search(r"hashlib\.", source):
            # There is hashing – make sure it is NOT md5
            assert not re.search(r"hashlib\.md5\b", source), (
                "hashlib.md5 is still used. Replace with an approved algorithm."
            )


# ---------------------------------------------------------------------------
# 4. Positive / regression – safe alternatives must remain functional
# ---------------------------------------------------------------------------

class TestSafeAlternativesStillWork:
    """Ensure the secure replacement patterns work correctly."""

    def test_pbkdf2_hmac_sha256_produces_correct_length(self):
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", b"s0me_p@ssword!", salt, 260_000)
        assert len(dk) == 32, "PBKDF2-HMAC-SHA256 should produce a 256-bit key."

    def test_sha256_hex_digest_length(self):
        digest = hashlib.sha256(b"test_input").hexdigest()
        assert len(digest) == 64

    def test_api_key_from_env_var_is_safe_pattern(self, monkeypatch):
        """Reading a secret from an environment variable does not embed it in source."""
        monkeypatch.setenv("MY_API_KEY", "sk-live-testvalue")
        key = os.environ.get("MY_API_KEY")
        assert key == "sk-live-testvalue"
        # The value is NOT in the source file
        assert "sk-live-testvalue" not in _load_source()

    def test_scrypt_kdf_works(self):
        """hashlib.scrypt is an approved memory-hard KDF for passwords."""
        salt = os.urandom(16)
        dk = hashlib.scrypt(b"password123", salt=salt, n=2**14, r=8, p=1, dklen=32)
        assert len(dk) == 32