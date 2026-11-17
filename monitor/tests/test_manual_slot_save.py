"""Manual slot edits never require model probes or security reports."""
import copy
import hashlib
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_monitor_recovery_integration import load_functions, nested
import conf_gate

SCRATCH = Path(os.environ["LOCALAPPDATA"]) / "hermes/cache/scratch"
SCRATCH.mkdir(parents=True, exist_ok=True)


def config():
    credentials = [
        dict(id=f"slot-{i}", provider="openai", model=f"fixture-{i}",
             api_base="https://api.example.com/v1", api_key=f"fixture-key-{i}")
        for i in range(4)
    ]
    return {"vlm": dict(credentials[0], credentials=credentials)}


class ManualSlotSaveTests(unittest.TestCase):
    def test_manual_policy_never_reads_reports_even_when_primary_is_changed(self):
        before = config()
        after = copy.deepcopy(before)
        after["vlm"]["credentials"][0]["model"] = "unaudited-primary"
        after["vlm"]["model"] = "unaudited-primary"
        with patch("provider_security_auditor.get_latest_audit_report",
                   side_effect=AssertionError("No audit lookup during manual save")) as audit:
            self.assertEqual([], conf_gate.validate_conf_targets(before, after, manual_save=True))
            audit.assert_not_called()

    def test_manual_policy_rejects_invalid_structure_and_secrets(self):
        invalid = [{}, {"vlm": []}, {"vlm": {"credentials": []}},
                   {"vlm": {"credentials": ["bad-slot"]}}]
        for field, value in [("model", ""), ("api_key", ""),
                             ("api_key", "${MISSING_MANUAL_SLOT_KEY}"),
                             ("api_key", "dpapi:invalid"),
                             ("api_base", "file:///fixture"),
                             ("api_base", "https://name:fixture-password@example.com/v1"),
                             ("api_base", "https://api.example.com:bad/v1")]:
            raw = config()
            raw["vlm"][field] = value
            raw["vlm"]["credentials"][0][field] = value
            invalid.append(raw)
        for raw in invalid:
            with self.subTest(vlm_type=type(raw.get("vlm")).__name__):
                with self.assertRaises(ValueError) as error:
                    conf_gate.validate_conf_targets(config(), raw, manual_save=True)
                self.assertNotIn("fixture-password", str(error.exception))
                self.assertNotIn("fixture-key", str(error.exception))

    def test_real_writer_promotes_backup_two_and_preserves_verified_backup(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            home = Path(directory) / ".openviking"
            app = home / "monitor"
            app.mkdir(parents=True)
            path = home / "ov.conf"
            before = config()
            before["embedding"] = {"dense": {"model": "fixture-embedding"}}
            path.write_bytes((json.dumps(before, indent=2).replace("\n", "\r\n") + "\r\n").encode())
            original_bytes = path.read_bytes()
            env = load_functions(CONF_PATH=path, OV_HOME=home, APP_DIR=app,
                                 APP_LOG=app / "app.log",
                                 _validate_conf_targets_policy=conf_gate.validate_conf_targets)
            import safe_write
            env.update(interprocess_file_lock=safe_write.interprocess_file_lock,
                       safe_atomic_write_json=safe_write.safe_atomic_write_json,
                       apply_restricted_file_acl=safe_write.apply_restricted_file_acl,
                       hashlib=hashlib, os=os, re=re, Path=Path)
            after = env["promote_slot"](copy.deepcopy(before), 2)
            with patch("provider_security_auditor.get_latest_audit_report",
                       side_effect=AssertionError("No audit lookup during real manual write")) as audit:
                backup = env["write_ov_conf_checked"](
                    after, env["_conf_digest"](before), before=before,
                    expected_advisories=[], manual_save=True)
                audit.assert_not_called()
            self.assertEqual(original_bytes, backup.read_bytes())
            self.assertEqual(after, json.loads(path.read_text(encoding="utf-8")))
            self.assertEqual(before["embedding"], after["embedding"])
            saved_bytes = path.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "changed during audit"):
                env["write_ov_conf_checked"](before, env["_conf_digest"](before),
                                              before=before, manual_save=True)
            self.assertEqual(saved_bytes, path.read_bytes())

    def test_promote_backup_two_without_any_audit_or_probe(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            path = Path(directory) / "ov.conf"
            before = config()
            path.write_text(json.dumps(before), encoding="utf-8")
            writer = Mock(return_value=Path("fixture-backup.json"))
            env = load_functions(
                CONF_PATH=path, _validate_conf_targets_policy=conf_gate.validate_conf_targets,
                AuditRequired=conf_gate.AuditRequired, messagebox=Mock(), log_app=Mock(),
                conf_digest=lambda _raw: "fixture-revision", write_ov_conf_checked=writer,
                start_inline_audit=Mock(),
            )
            env.update(current={"restarting": False}, ask_save=Mock(return_value="save"),
                       mark_pending=Mock(), begin_restart=Mock())
            nested(env, "apply_conf_edit")
            commit = nested(env, "commit_edit")
            with patch("provider_security_auditor.get_latest_audit_report",
                       side_effect=AssertionError("Manual saves must not query audits")) as audit:
                commit(lambda raw: env["promote_slot"](raw, 2), "promote backup two")
                audit.assert_not_called()
            env["mark_pending"].assert_called_once_with("promote backup two")
            env["begin_restart"].assert_not_called()
            writer.assert_called_once()
            saved = writer.call_args.args[0]
            self.assertEqual(["fixture-2", "fixture-0", "fixture-1", "fixture-3"],
                             [item["model"] for item in saved["vlm"]["credentials"]])
            self.assertEqual(saved["vlm"]["model"], "fixture-2")
            self.assertEqual(saved["vlm"]["api_key"], "fixture-key-2")
            self.assertTrue(writer.call_args.kwargs["manual_save"])
            env["start_inline_audit"].assert_not_called()
            env["messagebox"].askyesno.assert_not_called()
            env["messagebox"].askyesnocancel.assert_not_called()
            env["messagebox"].showerror.assert_not_called()
            self.assertEqual(before, json.loads(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
