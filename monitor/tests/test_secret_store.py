"""Unit tests for secret_store.py (DPAPI 64-bit safety, Fail-Loud, Env-Var Parsing, and Security Invariants)."""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import secret_store
from secret_store import (
    SecretStatus,
    dpapi_protect,
    dpapi_unprotect_strict,
    resolve_secret,
    is_env_ref,
    get_env_var_name,
)

class TestSecretStore(unittest.TestCase):
    def test_dpapi_roundtrip_and_gc_resilience(self):
        """Test encryption and decryption roundtrip under multiple GC passes."""
        import gc
        secret = "sk-test-secret-value-123456789"
        cipher = dpapi_protect(secret)
        self.assertTrue(cipher.startswith("dpapi:"))
        self.assertNotEqual(secret, cipher)

        # Force aggressive GC to test buffer retention
        gc.collect()

        res = dpapi_unprotect_strict(cipher)
        self.assertEqual(res.status, SecretStatus.SECRET_READY)
        self.assertEqual(res.value, secret)
        self.assertIsNone(res.error_message)

    def test_dpapi_corrupted_cipher_fails_loud(self):
        """Corrupted base64 or damaged DPAPI cipher must return DPAPI_UNAVAILABLE, never the cipher itself."""
        # 1. Invalid base64
        res1 = dpapi_unprotect_strict("dpapi:!!!not-base64!!!")
        self.assertEqual(res1.status, SecretStatus.DPAPI_UNAVAILABLE)
        self.assertEqual(res1.value, "")
        self.assertIn("Base64 decode failed", res1.error_message or "")

        # 2. Valid base64 but corrupted payload bytes
        import base64
        corrupted_payload = "dpapi:" + base64.b64encode(b"corrupted_non_dpapi_payload_bytes").decode("ascii")
        res2 = dpapi_unprotect_strict(corrupted_payload)
        self.assertEqual(res2.status, SecretStatus.DPAPI_UNAVAILABLE)
        self.assertEqual(res2.value, "")
        self.assertIn("CryptUnprotectData failed", res2.error_message or "")

    def test_env_var_resolution_valid(self):
        """Strict ${VAR} must resolve from environment dictionary."""
        mock_env = {"MY_SECRET_KEY": "sk-mock-key-from-env"}
        res = resolve_secret("${MY_SECRET_KEY}", env_dict=mock_env)
        self.assertEqual(res.status, SecretStatus.SECRET_READY)
        self.assertEqual(res.value, "sk-mock-key-from-env")
        self.assertEqual(res.env_var_name, "MY_SECRET_KEY")

    def test_env_var_resolution_missing(self):
        """Missing env var returns MISSING_ENVIRONMENT_VARIABLE."""
        mock_env = {}
        res = resolve_secret("${UNSET_VARIABLE}", env_dict=mock_env)
        self.assertEqual(res.status, SecretStatus.MISSING_ENVIRONMENT_VARIABLE)
        self.assertEqual(res.value, "")
        self.assertEqual(res.env_var_name, "UNSET_VARIABLE")
        self.assertIn("is not set", res.error_message or "")

    def test_env_var_resolution_empty(self):
        """Empty env var returns EMPTY_ENVIRONMENT_VARIABLE."""
        mock_env = {"EMPTY_VAR": "   "}
        res = resolve_secret("${EMPTY_VAR}", env_dict=mock_env)
        self.assertEqual(res.status, SecretStatus.EMPTY_ENVIRONMENT_VARIABLE)
        self.assertEqual(res.value, "")
        self.assertEqual(res.env_var_name, "EMPTY_VAR")
        self.assertIn("is empty", res.error_message or "")

    def test_malformed_env_syntax_rejected(self):
        """Malformed syntax like $VAR without braces, %VAR%, or Bearer ${VAR} is rejected."""
        malformed_cases = [
            "$SIMPLE_VAR",
            "%WINDOWS_VAR%",
            "Bearer ${KEY}",
            "${UNCLOSED_VAR",
            "prefix_${VAR}",
        ]
        for case in malformed_cases:
            res = resolve_secret(case, env_dict={"SIMPLE_VAR": "v", "KEY": "k"})
            self.assertEqual(
                res.status,
                SecretStatus.INVALID_SECRET_REFERENCE,
                f"Case '{case}' should have been rejected as INVALID_SECRET_REFERENCE but got {res.status}"
            )

    def test_invariant_never_returns_dpapi_as_secret_ready(self):
        """Invariant: No code path may return a value starting with 'dpapi:' with status SECRET_READY."""
        # 1. Direct cipher
        cipher = dpapi_protect("some-plain-secret")
        res1 = resolve_secret(cipher)
        self.assertFalse(res1.value.startswith("dpapi:"))

        # 2. Env var that resolves to a raw dpapi string (double envelope attempt)
        mock_env = {"NESTED_DPAPI": cipher}
        res2 = resolve_secret("${NESTED_DPAPI}", env_dict=mock_env)
        self.assertNotEqual(res2.status, SecretStatus.SECRET_READY)
        self.assertEqual(res2.status, SecretStatus.INVALID_SECRET_REFERENCE)

    def test_plaintext_passthrough(self):
        """Plain string without $ or dpapi: passes through as SECRET_READY."""
        plain = "sk-regular-openai-key-abc123xyz"
        res = resolve_secret(plain)
        self.assertEqual(res.status, SecretStatus.SECRET_READY)
        self.assertEqual(res.value, plain)

if __name__ == "__main__":
    unittest.main()
