"""Unit tests for backup_retention.py (Protected pins, keep_recent quota, dry-run, and non-destructive quarantine)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import backup_retention
from backup_retention import (
    is_protected_by_pattern,
    scan_backups,
    apply_quarantine,
    PERMANENTLY_PROTECTED_PATTERNS
)

class TestBackupRetention(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_protected_patterns(self):
        """Protected patterns must match key archives and never be candidate for pruning."""
        protected_names = [
            "cleanup-mem-ticks-20261026-004827",
            "OpenViking-Autostart-20260926-130755.xml",
            "ov.conf-CONTAMINATED-20261026-165527.json.bak",
            "ov.conf-before-slot-edit-20261112-030000-deadbeef.REJECTED.json",
            "live_safe_memories_20261012-142345",
            "mem-phase1-20261004-115356",
            "monitor-json-recovery",
            "quarantine"
        ]
        for name in protected_names:
            self.assertTrue(is_protected_by_pattern(name), f"{name} should be protected")

        unprotected_names = [
            "ov.conf-before-slot-edit-20260901-044458.json",
            "ov.conf-before-slot-edit-20261112-030000-0f499ad4.json",
            "ov.conf-before-slot-edit-20261112-030000-0f499ad4-1.json",
            "monitor-sync-20261025T162218Z-0887e30b"
        ]
        for name in unprotected_names:
            self.assertFalse(is_protected_by_pattern(name), f"{name} should NOT be protected by pattern alone")

    def test_scan_backups_keep_recent_quota(self):
        """Older snapshots beyond keep_recent threshold become candidates; recent ones are kept."""
        # Create 15 ov.conf snapshots with incremental mtimes
        import time
        now = time.time()
        for i in range(15):
            p = self.root / f"ov.conf-before-test-{i:02d}.json"
            p.write_text(f'{{"test": {i}}}', encoding="utf-8")
            # Set older mtime for lower index
            os.utime(p, (now - (15 - i) * 100, now - (15 - i) * 100))

        # Also create a protected archive
        prot = self.root / "cleanup-mem-test"
        prot.mkdir()
        (prot / "data.zip").write_text("fake zip", encoding="utf-8")

        # Scan with keep_recent=10
        plan = scan_backups(self.root, keep_recent=10)
        self.assertEqual(plan["total_items"], 16)
        # 1 protected archive + 10 kept ov.conf = 11 kept
        self.assertEqual(len(plan["kept"]), 11)
        # 5 oldest ov.conf become candidates
        self.assertEqual(plan["candidates_count"], 5)
        candidate_names = [c["name"] for c in plan["candidates"]]
        self.assertIn("ov.conf-before-test-00.json", candidate_names)
        self.assertIn("ov.conf-before-test-04.json", candidate_names)
        self.assertNotIn("ov.conf-before-test-14.json", candidate_names)

    def test_scan_backups_classifies_digest_suffixed_ov_conf_snapshots(self):
        import time
        now = time.time()
        for i in range(12):
            p = self.root / f"ov.conf-before-slot-edit-20261112-030000-0f499ad4-{i}.json"
            p.write_text(f'{{"index": {i}}}', encoding="utf-8")
            os.utime(p, (now - (12 - i) * 60, now - (12 - i) * 60))

        plan = scan_backups(self.root, keep_recent=10)
        self.assertEqual(plan["total_items"], 12)
        self.assertEqual(plan["protected_count"], 10)
        self.assertEqual(plan["candidates_count"], 2)
        candidate_names = [c["name"] for c in plan["candidates"]]
        self.assertEqual(
            sorted(candidate_names),
            [
                "ov.conf-before-slot-edit-20261112-030000-0f499ad4-0.json",
                "ov.conf-before-slot-edit-20261112-030000-0f499ad4-1.json",
            ],
        )

    def test_rejected_backup_is_never_candidate_even_with_keep_recent_zero(self):
        rejected = self.root / "ov.conf-before-slot-edit-20261112-030000-deadbeef.REJECTED.json"
        rejected.write_text('{"rejected": true}', encoding="utf-8")
        plan = scan_backups(self.root, keep_recent=0)
        self.assertEqual(plan["candidates_count"], 0)
        self.assertIn(rejected.name, plan["kept"])

    def test_apply_quarantine_moves_non_destructively(self):
        """apply_quarantine moves files to backups/quarantine/batch-<stamp> without deleting."""
        # Create 3 candidate files
        for i in range(3):
            (self.root / f"snap-{i}.json").write_text(f"content-{i}", encoding="utf-8")

        receipt = apply_quarantine(self.root, ["snap-0.json", "snap-1.json"])
        self.assertEqual(receipt["moved_count"], 2)

        # Original files should not exist in root
        self.assertFalse((self.root / "snap-0.json").exists())
        self.assertFalse((self.root / "snap-1.json").exists())
        # snap-2 was not in candidates, must remain
        self.assertTrue((self.root / "snap-2.json").exists())

        # Check quarantine directory
        quarantine_dir = self.root / "quarantine"
        self.assertTrue(quarantine_dir.is_dir())
        batches = list(quarantine_dir.glob("batch-*"))
        self.assertEqual(len(batches), 1)
        batch = batches[0]
        self.assertTrue((batch / "snap-0.json").is_file())
        self.assertTrue((batch / "snap-1.json").is_file())
        self.assertTrue((batch / "quarantine-manifest.json").is_file())

if __name__ == "__main__":
    unittest.main()
