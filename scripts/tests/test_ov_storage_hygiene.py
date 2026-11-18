"""Isolated unit tests for scripts/ov_storage_hygiene.py (protection invariants, 4 scopes, and plan digest gate)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import ov_storage_hygiene


class TestOvStorageHygiene(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ov_home = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _seed_tree(self, now: float) -> None:
        (self.ov_home / "ov.conf").write_text('{"server":{"port":19330}}', encoding="utf-8")

        # Protected baseline archive
        pre_dir = self.ov_home / "backups" / "pre-0.5.5-20261118-030029"
        pre_dir.mkdir(parents=True)
        (pre_dir / "snapshot.dat").write_bytes(b"baseline")

        # Quarantine item
        quar = self.ov_home / "backups" / "quarantine" / "batch-old"
        quar.mkdir(parents=True)
        (quar / "old_mon.json").write_text("{}", encoding="utf-8")

        # Monitor runtime vs underscore scratch
        mon = self.ov_home / "monitor"
        mon.mkdir(parents=True)
        (mon / "monitor.json").write_text("{}", encoding="utf-8")
        (mon / "safe_write.py").write_text("# core\n", encoding="utf-8")
        (mon / "_mem_junk_classify.py").write_text("# scratch\n", encoding="utf-8")
        (mon / "_cleanup_inventory.json").write_text("[]", encoding="utf-8")

        # Sessions: old cron session, recent cron session, and user session
        ud = self.ov_home / "data-qwen06b" / "viking" / "default" / "user" / "default"
        old_cron = ud / "sessions" / "cron_3db6_old"
        old_cron.mkdir(parents=True)
        old_msg = old_cron / "messages.jsonl"
        old_msg.write_text('{"role":"user"}\n', encoding="utf-8")
        os.utime(old_msg, (now - 10 * 86400, now - 10 * 86400))
        os.utime(old_cron, (now - 10 * 86400, now - 10 * 86400))

        fresh_cron = ud / "sessions" / "cron_3db6_fresh"
        fresh_cron.mkdir(parents=True)
        (fresh_cron / "messages.jsonl").write_text('{"role":"user"}\n', encoding="utf-8")

        user_sess = ud / "sessions" / "20261118_interactive"
        user_sess.mkdir(parents=True)
        u_msg = user_sess / "messages.jsonl"
        u_msg.write_text('{"role":"user"}\n', encoding="utf-8")
        os.utime(u_msg, (now - 30 * 86400, now - 30 * 86400))
        os.utime(user_sess, (now - 30 * 86400, now - 30 * 86400))

        # Memories: durable preference, milestone event, and tick receipt event
        prefs = ud / "memories" / "preferences"
        prefs.mkdir(parents=True)
        (prefs / "pref_keep.md").write_text("sc-cron-99 mentioned inside preference must still stay", encoding="utf-8")

        events = ud / "memories" / "events"
        events.mkdir(parents=True)
        (events / "OpenViking_migrado_v055.md").write_text("sc-cron-1 milestone keep", encoding="utf-8")
        (events / "mortalshell_installer_release.md").write_text(
            "Release milestone mentioning canonical SHA and exact_ordered_full_key_sha256",
            encoding="utf-8",
        )
        (events / "padronizacao_glossario_witch_trials.md").write_text(
            "Glossary standardization mentioning canonical SHA",
            encoding="utf-8",
        )
        (events / "commit_de_traducao_do_lote_42.md").write_text(
            "Batch tick sc-cron-42 validator errors = 0", encoding="utf-8"
        )

    def test_scan_and_selective_apply_preserve_all_protected_artifacts(self) -> None:
        now = time.time()
        self._seed_tree(now)

        plan = ov_storage_hygiene.scan_hygiene(self.ov_home, min_age_days=3.0, now_ts=now)
        self.assertIn("pre-0.5.5-20261118-030029", plan["protected_baselines_verified"])
        self.assertEqual(plan["summary"]["quarantine"]["items"], 1)
        self.assertEqual(plan["summary"]["monitor-scratch"]["items"], 2)
        self.assertEqual(plan["summary"]["cron-sessions"]["items"], 1)
        self.assertEqual(
            plan["candidates"]["cron-sessions"][0]["session_id"],
            "cron_3db6_old",
        )
        self.assertEqual(plan["summary"]["tick-events"]["items"], 1)
        self.assertTrue(
            plan["candidates"]["tick-events"][0]["uri"].endswith(
                "events/commit_de_traducao_do_lote_42.md"
            )
        )

        # Tampered digest must fail closed
        bad_plan = dict(plan)
        bad_plan["plan_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            ov_storage_hygiene.apply_hygiene_plan(
                self.ov_home, bad_plan, scopes=["quarantine"]
            )

        # Apply quarantine + monitor-scratch + cron-sessions
        receipt = ov_storage_hygiene.apply_hygiene_plan(
            self.ov_home,
            plan,
            scopes=["quarantine", "monitor-scratch", "cron-sessions"],
        )
        self.assertEqual(receipt["results"]["quarantine"]["removed_items"], 1)
        self.assertEqual(receipt["results"]["monitor-scratch"]["archived_files"], 2)
        self.assertEqual(receipt["results"]["cron-sessions"]["removed_sessions"], 1)

        # Protected files and recent/interactive sessions must remain untouched
        self.assertTrue((self.ov_home / "ov.conf").is_file())
        self.assertTrue((self.ov_home / "backups" / "pre-0.5.5-20261118-030029" / "snapshot.dat").is_file())
        self.assertTrue((self.ov_home / "monitor" / "monitor.json").is_file())
        self.assertTrue((self.ov_home / "monitor" / "safe_write.py").is_file())
        self.assertFalse((self.ov_home / "monitor" / "_mem_junk_classify.py").exists())
        ud = self.ov_home / "data-qwen06b" / "viking" / "default" / "user" / "default"
        self.assertTrue((ud / "sessions" / "cron_3db6_fresh").is_dir())
        self.assertTrue((ud / "sessions" / "20261118_interactive").is_dir())
        self.assertTrue((ud / "memories" / "preferences" / "pref_keep.md").is_file())
        self.assertTrue((ud / "memories" / "events" / "OpenViking_migrado_v055.md").is_file())

    def test_apply_rejects_non_loopback_url_and_forwards_resolved_root_api_key(self) -> None:
        now = time.time()
        self._seed_tree(now)
        (self.ov_home / "ov.conf").write_text(
            '{"server":{"port":19330,"root_api_key":"${TEST_OV_HYGIENE_ROOT_KEY}"}}',
            encoding="utf-8",
        )
        plan = ov_storage_hygiene.scan_hygiene(self.ov_home, min_age_days=3.0, now_ts=now)

        # Non-loopback URL must fail closed before mutating quarantine on disk
        with self.assertRaises(ValueError):
            ov_storage_hygiene.apply_hygiene_plan(
                self.ov_home,
                plan,
                scopes=["quarantine", "tick-events"],
                ov_url="http://example.com:19330",
            )
        self.assertTrue((self.ov_home / "backups" / "quarantine" / "batch-old").is_dir())

        captured: list[tuple[str, dict[str, str]]] = []

        class _DeleteHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_DELETE(self) -> None:
                captured.append(
                    (self.path, {k.lower(): v for k, v in self.headers.items()})
                )
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = HTTPServer(("127.0.0.1", 0), _DeleteHandler)
        port = srv.server_address[1]
        worker = threading.Thread(target=srv.serve_forever, daemon=True)
        worker.start()
        try:
            with mock.patch.dict(
                os.environ,
                {"TEST_OV_HYGIENE_ROOT_KEY": "SYNTHETIC_HYGIENE_KEY_888"},
                clear=False,
            ):
                receipt = ov_storage_hygiene.apply_hygiene_plan(
                    self.ov_home,
                    plan,
                    scopes=["tick-events"],
                    ov_url=f"http://127.0.0.1:{port}",
                )
        finally:
            srv.shutdown()
            srv.server_close()

        self.assertEqual(receipt["results"]["tick-events"]["api_deleted"], 1)
        self.assertEqual(receipt["results"]["tick-events"]["errors"], 0)
        self.assertEqual(len(captured), 1)
        req_path, req_headers = captured[0]
        self.assertIn("wait=true", req_path)
        self.assertEqual(req_headers.get("x-api-key"), "SYNTHETIC_HYGIENE_KEY_888")


if __name__ == "__main__":
    unittest.main()
