"""Tests for plan-first legacy ov.conf backup ACL retrofit (synthetic files only)."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))


@unittest.skipUnless(sys.platform == 'win32', 'Windows-only ACL and junction checks')
class TestRetrofitOvConfBackupAcl(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ov-retrofit-acl-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'backups'
        self.root.mkdir()
        self.sample = self.root / 'ov.conf-before-slot-edit-20261110-034841.json'
        self.payload = b'{"vlm":{"api_key":"${SYNTHETIC_KEY}"}}\r\n'
        self.sample.write_bytes(self.payload)
        self.unrelated = self.root / 'cleanup-mem-20261026.zip'
        self.unrelated.write_bytes(b'unrelated')
        self.sub = self.root / 'monitor-state'
        self.sub.mkdir()
        (self.sub / 'ov.conf-before-ignore.json').write_bytes(b'nested')

    def test_default_plan_only_does_not_modify_acls(self):
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        plan = mod.build_plan(self.root)
        self.assertEqual(plan['mode'], 'PLAN_ONLY')
        self.assertEqual(plan['total'], 1)
        self.assertEqual(plan['needs_harden'], 1)
        self.assertEqual(plan['files'][0]['name'], self.sample.name)
        self.assertTrue(plan['files'][0]['needs_harden'])
        # Confirm Everyone ACE was NOT removed in plan-only mode
        acl = mod._read_acl([self.sample])[str(self.sample.resolve())]
        self.assertIn(';;;WD)', acl['sddl_access'])

    def test_apply_hardens_acl_preserving_sha_size_and_mtime_ns(self):
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        before_stat = self.sample.stat()
        before_sha = hashlib.sha256(self.sample.read_bytes()).hexdigest()

        receipt = mod.apply_retrofit(self.root)
        self.assertEqual(receipt['mode'], 'APPLIED')
        self.assertEqual(receipt['hardened_count'], 1)
        self.assertTrue(receipt['all_sha256_size_mtime_unchanged'])
        self.assertTrue(receipt['all_protected_exact_dacl'])

        after_stat = self.sample.stat()
        self.assertEqual(hashlib.sha256(self.sample.read_bytes()).hexdigest(), before_sha)
        self.assertEqual(after_stat.st_size, before_stat.st_size)
        self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)
        acl = mod._read_acl([self.sample])[str(self.sample.resolve())]
        self.assertIsInstance(acl['protected'], bool)
        self.assertIsInstance(acl['exact_dacl'], bool)
        self.assertTrue(acl['protected'])
        self.assertTrue(acl['exact_dacl'])
        self.assertNotIn(';;;WD)', acl['sddl_access'])

        # Second pass is an idempotent no-op
        second = mod.apply_retrofit(self.root)
        self.assertEqual(second['hardened_count'], 0)

    def test_rejects_junction_backup_root_before_any_change(self):
        import retrofit_ov_conf_backup_acl as mod

        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        (outside / 'ov.conf-before-outside.json').write_bytes(b'{}')
        junction = Path(self.tmp.name) / 'junction-backups'
        res = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(junction), str(outside)],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(res.returncode, 0, res.stderr)
        try:
            with self.assertRaisesRegex(ValueError, 'reparse|Unsafe'):
                mod.build_plan(junction)
        finally:
            os.rmdir(junction)

    def test_pre_apply_hash_drift_aborts_without_modifying_target(self):
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        plan = mod.build_plan(self.root)
        self.sample.write_bytes(b'{"drifted":true}\n')
        with patch.object(mod, 'build_plan', return_value=plan):
            with self.assertRaisesRegex(RuntimeError, 'hash drift'):
                mod.apply_retrofit(self.root)
        acl = mod._read_acl([self.sample])[str(self.sample.resolve())]
        self.assertIn(';;;WD)', acl['sddl_access'])

    def test_skips_rejected_contaminated_and_non_json_while_reporting_them(self):
        import retrofit_ov_conf_backup_acl as mod

        skipped_names = [
            'ov.conf-before-slot-edit-20261112-030000-deadbeef.REJECTED.json',
            'ov.conf-before-CONTAMINATED-20261026.json',
            'ov.conf-before-slot-edit-20261112-030000.txt',
        ]
        for name in skipped_names:
            (self.root / name).write_bytes(b'{}')
        plan = mod.build_plan(self.root)
        self.assertEqual(plan['total'], 1)
        self.assertEqual(sorted(plan['skipped_protected']), sorted(skipped_names))

    def test_partial_failure_writes_audit_receipt_and_raises(self):
        import retrofit_ov_conf_backup_acl as mod

        second = self.root / 'ov.conf-before-slot-edit-20261110-034842.json'
        second.write_bytes(self.payload)
        for p in (self.sample, second):
            subprocess.run(['icacls', str(p), '/grant', '*S-1-1-0:(R)'],
                           capture_output=True, check=True, timeout=10)
        receipt_path = Path(self.tmp.name) / 'partial-receipt.json'
        calls = []

        def fail_second(path):
            calls.append(Path(path).name)
            return len(calls) == 1

        with patch.object(mod, 'apply_restricted_file_acl', side_effect=fail_second):
            with self.assertRaises(PermissionError):
                mod.apply_retrofit(self.root, receipt_path=receipt_path)
        partial = json.loads(receipt_path.read_text(encoding='utf-8'))
        self.assertEqual(partial['mode'], 'APPLY_PARTIAL')
        self.assertEqual(partial['hardened_count'], 1)
        self.assertEqual(partial['hardened_names'], [self.sample.name])
        self.assertEqual(partial['error_class'], 'PermissionError')


if __name__ == '__main__':
    unittest.main()
