"""Tests for Windows DPAPI encryption and env-var transparency."""
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import runpy

class TestKeyHardening(unittest.TestCase):
    def setUp(self):
        self.ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='dpapi_test')

    def test_dpapi_roundtrip(self):
        dpapi_protect = self.ns['dpapi_protect']
        dpapi_unprotect = self.ns['dpapi_unprotect']
        
        secret = "sk-test-secret-12345"
        encrypted = dpapi_protect(secret)
        if sys.platform == 'win32':
            self.assertTrue(encrypted.startswith("dpapi:"))
            self.assertNotEqual(secret, encrypted)
            decrypted = dpapi_unprotect(encrypted)
            self.assertEqual(secret, decrypted)
        else:
            self.assertEqual(secret, encrypted)

    def test_dpapi_passthrough_non_dpapi(self):
        dpapi_unprotect = self.ns['dpapi_unprotect']
        plain = "sk-regular-plain-key"
        self.assertEqual(dpapi_unprotect(plain), plain)
        self.assertEqual(dpapi_unprotect(""), "")

if __name__ == '__main__':
    unittest.main()
