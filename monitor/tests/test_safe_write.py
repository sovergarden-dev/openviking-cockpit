"""Unit tests for safe_write.py (Atomic replacement, SHA-256 verification, revision check, and interprocess lock)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import safe_write
from safe_write import (
    safe_atomic_write_text,
    safe_atomic_write_json,
    interprocess_file_lock,
    apply_restricted_file_acl,
)

class TestSafeWrite(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_safe_atomic_write_text_creates_file(self):
        """Atomic write creates destination file with exact content and returns SHA-256."""
        target = self.root / "test_target.txt"
        content = "hello world\nline 2"
        sha = safe_atomic_write_text(target, content, restrict_acl=False)
        self.assertTrue(target.is_file())
        self.assertEqual(target.read_text(encoding="utf-8"), content)
        self.assertEqual(len(sha), 64)

    def test_safe_atomic_write_json(self):
        """Atomic write JSON parses cleanly and preserves format."""
        target = self.root / "config.json"
        data = {"model": "test-vlm", "slots": [1, 2, 3], "enabled": True}
        sha = safe_atomic_write_json(target, data, indent=2, restrict_acl=False)
        self.assertTrue(target.is_file())
        loaded = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(loaded, data)

    def test_revision_mismatch_blocks_write(self):
        """Revision check: if destination has changed from expected SHA, write is rejected."""
        target = self.root / "state.json"
        safe_atomic_write_text(target, "initial content", restrict_acl=False)

        # Attempt to write with wrong expected SHA
        with self.assertRaises(ValueError) as ctx:
            safe_atomic_write_text(target, "new content", expected_previous_sha="wrong_sha_00000000", restrict_acl=False)
        self.assertIn("Revision mismatch", str(ctx.exception))
        # Ensure file content was not modified
        self.assertEqual(target.read_text(encoding="utf-8"), "initial content")

    def test_interprocess_lock_context(self):
        """Interprocess lock acquires and releases cleanly."""
        lock_file = self.root / ".writer.lock"
        with interprocess_file_lock(lock_file, timeout_seconds=2.0):
            self.assertTrue(lock_file.is_file())
            # Target action inside lock
            target = self.root / "locked_write.txt"
            safe_atomic_write_text(target, "data under lock", restrict_acl=False)
            self.assertEqual(target.read_text(encoding="utf-8"), "data under lock")

    def test_temp_file_cleaned_up_on_disk(self):
        """After atomic replace, no leftover .tmp files remain in directory."""
        target = self.root / "cleanup_target.json"
        safe_atomic_write_text(target, "data", restrict_acl=False)
        tmp_files = list(self.root.glob(".*.tmp"))
        self.assertEqual(len(tmp_files), 0)

if __name__ == "__main__":
    unittest.main()
