"""
Security tests for rd_fix_demo.py

Targets:
1. Hardcoded API key / secret leakage
2. Weak hashing algorithm (MD5 used for password digest)
3. Hardcoded plaintext password
"""

import ast
import importlib
import importlib.util
import inspect
import os
import re
import sys
import hashlib
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helper – load the source text without executing it where possible
# ---------------------------------------------------------------------------
SOURCE_FILE = Path(__file__).parent.parent / "rd_fix_demo.py"
SOURCE_TEXT = SOURCE_FILE.read_text() if SOURCE_FILE.exists() else ""


def _load_module():
    """Import the module under test, return it."""
    spec = importlib.util.spec_from_file_location("rd_fix_demo", SOURCE_FILE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ===========================================================================
# 1. Hardcoded API key tests
# ===========================================================================

class TestHardcodedApiKey:
    """API keys must never be committed in plaintext source code."""

    # Common live-key prefixes / patterns
    API_KEY_PATTERNS = [
        re.compile(r'sk[-_]live[-_][A-Za-z0-9]+'),
        re.compile(r'(?<![A-Za-z0-9])sk-[A-Za-z0-9]{16,}'),
        re.compile(r'API_KEY\s*=\s*["\'][^"\']+["\']'),
    ]

    def test_no_hardcoded_api_key_in_source(self):
        """Source file must NOT contain a literal API key assignment."""
        for pattern in self.API_KEY_PATTERNS:
            assert not pattern.search(SOURCE_TEXT), (
                f"Hardcoded API key pattern '{pattern.pattern}' found in source. "
                "Use environment variables or a secret manager instead."
            )

    def test_api_key_not_exposed_as_module_attribute(self):
        """The module must not expose a plaintext API_KEY at module level."""
        mod = _load_module()
        if not hasattr(mod, "API_KEY"):
            return  # already removed – pass
        api_key_value = mod.API_KEY
        # It should either be None, an empty string, or sourced from env
        assert api_key_value in (None, ""), (
            f"API_KEY is set to a live value '{api_key_value[:6]}…' in module scope. "
            "Secrets must be loaded from environment variables, not hardcoded."
        )

    def test_api_key_resembles_live_key_format(self):
        """If an API_KEY symbol exists it must NOT match the 'sk-live-…' live-key pattern."""
        mod = _load_module()
        value = getattr(mod, "API_KEY", "")
        live_pattern = re.compile(r'^sk[-_]live[-_]', re.IGNORECASE)
        assert not live_pattern.match(str(value)), (
            "API_KEY looks like a live/production secret. "
            "Store secrets in environment variables (os.getenv) or a vault."
        )

    def test_api_key_should_come_from_environment(self):
        """
        Demonstrate the SAFE pattern: reading from env returns a value
        without baking it into source code.
        """
        os.environ["API_KEY_TEST"] = "sk-live-testvalue"
        retrieved = os.environ.get("API_KEY_TEST")
        assert retrieved == "sk-live-testvalue"
        # Cleanup
        del os.environ["API_KEY_TEST"]


# ===========================================================================
# 2. Weak cryptography – MD5 used for password hashing
# ===========================================================================

class TestWeakCryptoMd5:
    """MD5 must not be used for password storage."""

    def test_source_does_not_use_md5_for_password(self):
        """Source must not call hashlib.md5 in a password-hashing context."""
        # Look for the pattern: md5 used on something called 'password'
        dangerous_pattern = re.compile(
            r'hashlib\.md5\s*\(\s*password', re.IGNORECASE
        )
        assert not dangerous_pattern.search(SOURCE_TEXT), (
            "MD5 is cryptographically broken and must NOT be used for password "
            "hashing. Use hashlib.scrypt, bcrypt, argon2, or hashlib.pbkdf2_hmac."
        )

    def test_no_bare_md5_call_in_source(self):
        """Source must not contain any hashlib.md5() call at all."""
        assert "hashlib.md5" not in SOURCE_TEXT, (
            "hashlib.md5 is present in the source. MD5 is unsuitable for "
            "password storage or security-sensitive digests."
        )

    def test_module_digest_is_not_md5(self):
        """If a 'digest' attribute exists it must not be an MD5 hex digest of a known password."""
        mod = _load_module()
        digest = getattr(mod, "digest", None)
        if digest is None:
            return  # removed – pass

        # MD5("hunter2") is a well-known value
        known_md5 = hashlib.md5(b"hunter2").hexdigest()
        assert digest != known_md5, (
            f"Module 'digest' equals the MD5 hash of the hardcoded password "
            f"'{known_md5}'. MD5 is not safe for password storage."
        )

    def test_safe_password_hashing_works(self):
        """Show that a safe algorithm (pbkdf2_hmac/sha256) is usable."""
        password = "hunter2"
        salt = os.urandom(16)
        safe_digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, iterations=260_000
        )
        assert len(safe_digest) == 32, "pbkdf2_hmac with sha256 should return 32 bytes"

    def test_md5_collision_resistance_is_broken(self):
        """
        Verify MD5 is considered weak: Python's hashlib exposes it as
        non-guaranteed-secure; we simply assert it must not be the algorithm
        used for passwords by checking the usedforsecurity flag is False
        when it IS used (i.e. caller must acknowledge insecurity).
        """
        # This is how MD5 *may* be used legitimately (non-security checksum),
        # but only with usedforsecurity=False on Python ≥ 3.9.
        try:
            _ = hashlib.md5(b"data", usedforsecurity=False)
        except TypeError:
            pytest.skip("Python < 3.9 – usedforsecurity kwarg unavailable")

        # The module under test calls hashlib.md5 WITHOUT usedforsecurity=False,
        # meaning it is implicitly declaring security use – which is wrong.
        tree = ast.parse(SOURCE_TEXT)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "md5"
            ):
                keywords = {kw.arg for kw in node.keywords}
                assert "usedforsecurity" in keywords and any(
                    kw.arg == "usedforsecurity"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                    for kw in node.keywords
                ), (
                    "hashlib.md5() is called without usedforsecurity=False. "
                    "Either remove the MD5 call or mark it explicitly non-security."
                )


# ===========================================================================
# 3. Hardcoded plaintext password
# ===========================================================================

class TestHardcodedPassword:
    """Passwords must never appear in source code."""

    KNOWN_PASSWORDS = ["hunter2", "password", "admin", "secret", "123456"]

    def test_no_hardcoded_password_literal_in_source(self):
        """Source must not contain a literal password assignment."""
        password_assignment = re.compile(
            r'password\s*=\s*["\'](?P<val>[^"\']+)["\']', re.IGNORECASE
        )
        match = password_assignment.search(SOURCE_TEXT)
        assert not match, (
            f"Hardcoded password '{match.group('val') if match else '?'}' "
            "found in source. Load credentials from environment variables "
            "or a secret store."
        )

    def test_password_attribute_not_plaintext_string(self):
        """Module-level 'password' must not be a non-empty plaintext string."""
        mod = _load_module()
        pw = getattr(mod, "password", None)
        assert not (isinstance(pw, str) and pw.strip()), (
            "Module exports a plaintext 'password' string. "
            "Never store credentials in source."
        )

    @pytest.mark.parametrize("known_pw", KNOWN_PASSWORDS)
    def test_known_password_not_in_source(self, known_pw):
        """Common/known passwords must not appear verbatim in source."""
        assert known_pw not in SOURCE_TEXT, (
            f"Known password '{known_pw}' found literally in the source file."
        )

    def test_safe_password_loading_from_env(self):
        """Demonstrate the safe pattern: load passwords from environment."""
        os.environ["APP_PASSWORD"] = "some-runtime-secret"
        pw = os.environ.get("APP_PASSWORD")
        assert pw is not None
        assert pw not in SOURCE_TEXT, (
            "Even the env-loaded password must not appear in source."
        )
        del os.environ["APP_PASSWORD"]


# ===========================================================================
# 4. AST-level static analysis (catch obfuscated variants)
# ===========================================================================

class TestAstStaticAnalysis:
    """Parse the AST to catch secrets/weak-crypto regardless of formatting."""

    def _get_string_literals(self):
        tree = ast.parse(SOURCE_TEXT)
        return [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]

    def test_no_string_matches_api_key_pattern_in_ast(self):
        live_key = re.compile(r'^sk[-_]live[-_]', re.IGNORECASE)
        for literal in self._get_string_literals():
            assert not live_key.match(literal), (
                f"String literal '{literal[:12]}…' looks like a live API key."
            )

    def test_no_string_matches_known_password_in_ast(self):
        known = {"hunter2", "password", "admin", "secret"}
        for literal in self._get_string_literals():
            assert literal not in known, (
                f"String literal '{literal}' is a known weak/hardcoded password."
            )

    def test_hashlib_md5_not_called_in_ast(self):
        tree = ast.parse(SOURCE_TEXT)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "md5"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
            ):
                pytest.fail(
                    "hashlib.md5() call detected in AST. "
                    "Replace with a secure KDF (scrypt, bcrypt, argon2, pbkdf2_hmac)."
                )