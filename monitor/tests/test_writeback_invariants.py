"""Unit tests for write-back invariants and anti-leakage gates."""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import runpy
import secret_store
from secret_store import SecretStatus, dpapi_protect, dpapi_unprotect_strict
import conf_gate

class TestWritebackInvariants(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        # Mock paths for openviking-monitor.pyw
        self.conf_path = self.root / "ov.conf"
        self.state_path = self.root / "monitor.json"
        self.app_dir = self.root / "monitor"
        self.app_dir.mkdir(parents=True, exist_ok=True)

        # Setup initial ov.conf with an explicit env var reference ${MOCK_SLOT_KEY}
        self.initial_ov = {
            "vlm": {
                "model": "gemini-3.8-flash",
                "api_base": "http://127.0.0.1:20128/v1",
                "api_key": "${MOCK_TOP_KEY}",
                "credentials": [
                    {
                        "id": "slot-0",
                        "model": "gemini-3.8-flash",
                        "api_base": "http://127.0.0.1:20128/v1",
                        "api_key": "${MOCK_SLOT_KEY}"
                    }
                ]
            }
        }
        self.conf_path.write_text(json.dumps(self.initial_ov, indent=2), encoding="utf-8")

        # Mock USERPROFILE environment variable before loading openviking-monitor.pyw
        self._orig_userprofile = os.environ.get("USERPROFILE")
        os.environ["USERPROFILE"] = str(self.root)
        fake_ov = self.root / ".openviking"
        fake_ov.mkdir(parents=True, exist_ok=True)
        (fake_ov / "ov.conf").write_text(json.dumps(self.initial_ov, indent=2), encoding="utf-8")
        (fake_ov / "monitor").mkdir(parents=True, exist_ok=True)

        # Load openviking-monitor namespace in safe isolation
        self.ns = runpy.run_path(str(ROOT / "openviking-monitor.pyw"), run_name="invariants_test")
        self.ns["_validate_conf_targets_policy"] = conf_gate.validate_conf_targets
        self.ns["AuditRequired"] = conf_gate.AuditRequired
        self.ns["compute_conf_drift"] = conf_gate.compute_conf_drift
        self.ns["validate_conf_targets"] = conf_gate.validate_conf_targets
        import contextlib
        self.ns["interprocess_file_lock"] = lambda _path: contextlib.nullcontext()
        self.ns["safe_atomic_write_json"] = lambda path, data, **_kwargs: path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.ns["backup_ov_conf"] = self._make_backup
        # Override paths in namespace and in functions' globals
        self.ns["CONF_PATH"] = self.conf_path
        self.ns["STATE_PATH"] = self.state_path
        self.ns["APP_DIR"] = self.app_dir
        for fn_name in ["read_ov_conf_raw", "read_ov_conf", "write_ov_conf", "load_state", "save_state"]:
            if fn_name in self.ns and hasattr(self.ns[fn_name], "__globals__"):
                self.ns[fn_name].__globals__["CONF_PATH"] = self.conf_path
                self.ns[fn_name].__globals__["STATE_PATH"] = self.state_path
                self.ns[fn_name].__globals__["APP_DIR"] = self.app_dir

    def _make_backup(self, reason):
        backup = self.root / f"backup-{reason}.json"
        backup.write_bytes(self.conf_path.read_bytes())
        return backup

    def tearDown(self):
        if self._orig_userprofile is not None:
            os.environ["USERPROFILE"] = self._orig_userprofile
        self.tmp_dir.cleanup()

    def test_read_ov_conf_raw_preserves_env_var(self):
        """read_ov_conf_raw returns raw dict with exact ${MOCK_SLOT_KEY} string."""
        raw = self.ns["read_ov_conf_raw"]()
        creds = raw["vlm"]["credentials"]
        self.assertEqual(creds[0]["api_key"], "${MOCK_SLOT_KEY}")

    def test_metadata_edit_preserves_raw_env_var_on_write(self):
        """Editing model name preserves ${MOCK_SLOT_KEY} in ov.conf without expanding to plain secret."""
        # Simulate environment containing the actual secret
        os.environ["MOCK_SLOT_KEY"] = "sk-super-secret-12345"
        try:
            raw = self.ns["read_ov_conf_raw"]()
            # Update only model name
            raw["vlm"]["credentials"][0]["model"] = "new-gemini-model"
            self.ns["write_ov_conf"](raw)

            # Re-read raw text from disk directly
            saved_text = self.conf_path.read_text(encoding="utf-8")
            # Invariant: ${MOCK_SLOT_KEY} must be present; plain secret must NOT be present
            self.assertIn("${MOCK_SLOT_KEY}", saved_text)
            self.assertNotIn("sk-super-secret-12345", saved_text)
        finally:
            os.environ.pop("MOCK_SLOT_KEY", None)

    def test_checked_writer_rejects_stale_audit_snapshot_without_backup(self):
        changed = json.loads(self.conf_path.read_text(encoding="utf-8"))
        changed["vlm"]["model"] = "concurrent-model"
        self.conf_path.write_text(json.dumps(changed), encoding="utf-8")
        raw_candidate = json.loads(json.dumps(changed))
        with self.assertRaisesRegex(RuntimeError, "changed during audit"):
            self.ns["write_ov_conf_checked"](raw_candidate, "stale-digest")

    def test_checked_writer_revalidates_policy_while_locked(self):
        baseline = self.ns["read_ov_conf_raw"]()
        candidate = json.loads(json.dumps(baseline))
        candidate["vlm"]["credentials"][0]["model"] = "new-gemini-model"
        # The policy must be invoked again by the checked writer under its lock.
        validate_globals = self.ns["write_ov_conf_checked"].__globals__
        original_policy = validate_globals["validate_conf_targets"]
        policy = Mock(return_value=[])
        validate_globals["validate_conf_targets"] = policy
        try:
            backup = self.ns["write_ov_conf_checked"](
                candidate,
                self.ns["_conf_digest"](baseline),
                before=baseline,
                expected_advisories=[],
            )
        finally:
            validate_globals["validate_conf_targets"] = original_policy
        policy.assert_called_once_with(baseline, candidate)
        self.assertTrue(backup.is_file())
        self.assertEqual(json.loads(self.conf_path.read_text(encoding="utf-8")), candidate)

    def test_checked_writer_rolls_back_only_its_own_failed_publish(self):
        baseline = self.ns["read_ov_conf_raw"]()
        candidate = json.loads(json.dumps(baseline))
        candidate["vlm"]["credentials"][0]["model"] = "partial-write-model"
        writer_globals = self.ns["write_ov_conf_checked"].__globals__
        old_writer = writer_globals["safe_atomic_write_json"]
        calls = {"count": 0}
        def fail_after_publish(path, data, **kwargs):
            calls["count"] += 1
            old_writer(path, data, **kwargs)
            if calls["count"] == 1:
                raise OSError("injected post-publish failure")
        writer_globals["safe_atomic_write_json"] = fail_after_publish
        writer_globals["validate_conf_targets"] = lambda _before, _after: []
        try:
            with self.assertRaisesRegex(OSError, "injected post-publish"):
                self.ns["write_ov_conf_checked"](
                    candidate,
                    self.ns["_conf_digest"](baseline),
                    before=baseline,
                    expected_advisories=[],
                )
        finally:
            writer_globals["safe_atomic_write_json"] = old_writer
            writer_globals["validate_conf_targets"] = conf_gate.validate_conf_targets
        self.assertEqual(json.loads(self.conf_path.read_text(encoding="utf-8")), baseline)

    def test_checked_writer_preserves_newer_concurrent_content_on_rollback_path(self):
        baseline = self.ns["read_ov_conf_raw"]()
        candidate = json.loads(json.dumps(baseline))
        candidate["vlm"]["credentials"][0]["model"] = "attempted-model"
        concurrent = json.loads(json.dumps(baseline))
        concurrent["vlm"]["credentials"][0]["model"] = "concurrent-newer-model"
        writer_globals = self.ns["write_ov_conf_checked"].__globals__
        old_writer = writer_globals["safe_atomic_write_json"]
        calls = {"count": 0}
        def simulate_concurrent_change(path, data, **kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                path.write_text(json.dumps(data, indent=2), encoding="utf-8")
                path.write_text(json.dumps(concurrent, indent=2), encoding="utf-8")
                raise OSError("injected write failure after concurrent edit")
            return old_writer(path, data, **kwargs)
        writer_globals["safe_atomic_write_json"] = simulate_concurrent_change
        writer_globals["validate_conf_targets"] = lambda _before, _after: []
        try:
            with self.assertRaisesRegex(RuntimeError, "newer contents were preserved"):
                self.ns["write_ov_conf_checked"](
                    candidate,
                    self.ns["_conf_digest"](baseline),
                    before=baseline,
                    expected_advisories=[],
                )
        finally:
            writer_globals["safe_atomic_write_json"] = old_writer
            writer_globals["validate_conf_targets"] = conf_gate.validate_conf_targets
        self.assertEqual(json.loads(self.conf_path.read_text(encoding="utf-8")), concurrent)

    def test_write_ov_conf_rejects_dpapi_cipher(self):
        """write_ov_conf rejects any credential starting with dpapi:."""
        bad_raw = {
            "vlm": {
                "model": "test",
                "credentials": [
                    {"model": "m", "api_key": "dpapi:AQAAANCMnd8BFdERjHoAwE..."}
                ]
            }
        }
        with self.assertRaises(ValueError) as ctx:
            self.ns["write_ov_conf"](bad_raw)
        self.assertIn("chứa chuỗi mã hóa dpapi:", str(ctx.exception))

    def test_save_state_preserves_exact_dpapi_blob_when_key_unchanged(self):
        """Editing spare model note preserves exact original dpapi: ciphertext byte-for-byte."""
        cipher = dpapi_protect("sk-my-spare-secret")
        initial_state = {
            "spare_models": [
                {
                    "model": "spare-1",
                    "api_key": cipher,
                    "note": "old note"
                }
            ]
        }
        self.state_path.write_text(json.dumps(initial_state, indent=2), encoding="utf-8")

        # load state in monitor
        loaded = self.ns["load_state"]()
        spares = loaded["spare_models"]
        self.assertEqual(len(spares), 1)
        self.assertEqual(spares[0]["_enc"], cipher)
        self.assertEqual(spares[0]["api_key"], "sk-my-spare-secret")

        # Modify only the note
        spares[0]["note"] = "updated note"
        self.ns["save_state"](loaded)

        # Inspect disk state
        after_data = json.loads(self.state_path.read_text(encoding="utf-8"))
        saved_spare = after_data["spare_models"][0]
        self.assertEqual(saved_spare["note"], "updated note")
        # Invariant: exact cipher preserved byte-for-byte
        self.assertEqual(saved_spare["api_key"], cipher)

    def test_save_state_preserves_dpapi_when_locked(self):
        """If DPAPI is locked (decryption failed/unavailable), save_state preserves raw cipher."""
        corrupted_cipher = "dpapi:corrupted_blob_not_decryptable"
        initial_state = {
            "spare_models": [
                {
                    "model": "spare-locked",
                    "api_key": corrupted_cipher,
                    "note": ""
                }
            ]
        }
        self.state_path.write_text(json.dumps(initial_state, indent=2), encoding="utf-8")

        loaded = self.ns["load_state"]()
        spares = loaded["spare_models"]
        self.assertTrue(spares[0]["_dpapi_locked"])
        self.assertEqual(spares[0]["api_key"], "")

        # Save state without user entering a new key
        self.ns["save_state"](loaded)

        # Invariant: corrupted cipher is preserved, not overwritten with empty string
        after_data = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(after_data["spare_models"][0]["api_key"], corrupted_cipher)

if __name__ == "__main__":
    unittest.main()
