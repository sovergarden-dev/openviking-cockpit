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

    def test_plan_and_receipt_omit_raw_sddl_and_sid(self):
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        plan = mod.build_plan(self.root)
        plan_json = json.dumps(plan)
        self.assertNotIn('S-1-5-', plan_json)
        self.assertNotIn('sddl_access', plan['files'][0])
        self.assertEqual(len(plan['files'][0]['sddl_sha256']), 64)

        receipt = mod.apply_retrofit(self.root)
        receipt_json = json.dumps(receipt)
        self.assertNotIn('S-1-5-', receipt_json)
        self.assertNotIn('sddl_after', receipt['files'][0])
        self.assertEqual(len(receipt['files'][0]['sddl_after_sha256']), 64)

    def test_plan_file_matching_applies_and_records_plan_sha256(self):
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        plan = mod.build_plan(self.root)
        plan_path = Path(self.tmp.name) / 'reviewed-plan.json'
        plan_bytes = (json.dumps(plan, indent=2) + '\n').encode('utf-8')
        plan_path.write_bytes(plan_bytes)
        expected_plan_sha = hashlib.sha256(plan_bytes).hexdigest()

        receipt = mod.apply_retrofit(self.root, plan_file=plan_path)
        self.assertEqual(receipt['mode'], 'APPLIED')
        self.assertEqual(receipt['hardened_count'], 1)
        self.assertEqual(receipt['plan_sha256'], expected_plan_sha)

    def test_plan_file_rejects_drift_wrong_mode_outside_path_and_backup_dir_mismatch(self):
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        plan = mod.build_plan(self.root)
        plan_path = Path(self.tmp.name) / 'bad-plan.json'
        receipt_path = Path(self.tmp.name) / 'aborted-receipt.json'

        # 1) wrong mode
        wrong_mode = dict(plan, mode='APPLIED')
        plan_path.write_text(json.dumps(wrong_mode), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'PLAN_ONLY'):
            mod.apply_retrofit(self.root, receipt_path=receipt_path, plan_file=plan_path)
        self.assertEqual(json.loads(receipt_path.read_text(encoding='utf-8'))['mode'], 'APPLY_ABORTED')

        # 2) backup_dir mismatch
        other_dir = Path(self.tmp.name) / 'other-backups'
        other_dir.mkdir()
        wrong_dir = dict(plan, backup_dir=str(other_dir))
        plan_path.write_text(json.dumps(wrong_dir), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'backup_dir'):
            mod.apply_retrofit(self.root, plan_file=plan_path)

        # 3) path outside backup_dir
        outside_plan = json.loads(json.dumps(plan))
        outside_plan['files'][0]['path'] = str(Path(self.tmp.name) / 'outside.json')
        plan_path.write_text(json.dumps(outside_plan), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'outside'):
            mod.apply_retrofit(self.root, plan_file=plan_path)

        # 4) file drift after plan generation
        plan_path.write_text(json.dumps(plan), encoding='utf-8')
        self.sample.write_bytes(b'{"changed":true}\n')
        with self.assertRaisesRegex(RuntimeError, 'drift'):
            mod.apply_retrofit(self.root, receipt_path=receipt_path, plan_file=plan_path)
        self.assertEqual(json.loads(receipt_path.read_text(encoding='utf-8'))['mode'], 'APPLY_ABORTED')
        acl = mod._read_acl([self.sample])[str(self.sample.resolve())]
        self.assertIn(';;;WD)', acl['sddl_access'])

    def test_plan_file_rejects_reparse_and_malformed_json(self):
        import retrofit_ov_conf_backup_acl as mod

        bad_json = Path(self.tmp.name) / 'malformed.json'
        bad_json.write_text('{', encoding='utf-8')
        with self.assertRaises(ValueError):
            mod.apply_retrofit(self.root, plan_file=bad_json)

        outside = Path(self.tmp.name) / 'outside-dir'
        outside.mkdir()
        (outside / 'plan.json').write_text('{}', encoding='utf-8')
        junc = Path(self.tmp.name) / 'junc-dir'
        res = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(junc), str(outside)],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(res.returncode, 0, res.stderr)
        try:
            with patch.object(mod, '_has_reparse_point', side_effect=lambda p: p == junc / 'plan.json'):
                with self.assertRaisesRegex(ValueError, 'reparse'):
                    mod.apply_retrofit(self.root, plan_file=junc / 'plan.json')
        finally:
            os.rmdir(junc)

    def test_keyboard_interrupt_writes_apply_partial_receipt_and_reraises(self):
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        receipt_path = Path(self.tmp.name) / 'interrupt-receipt.json'
        with patch.object(mod, 'apply_restricted_file_acl', side_effect=KeyboardInterrupt('cancelled')):
            with self.assertRaises(KeyboardInterrupt):
                mod.apply_retrofit(self.root, receipt_path=receipt_path)
        partial = json.loads(receipt_path.read_text(encoding='utf-8'))
        self.assertEqual(partial['mode'], 'APPLY_PARTIAL')
        self.assertEqual(partial['error_class'], 'KeyboardInterrupt')

    def test_mixed_acl_order_alignment_and_non_ascii_filename(self):
        import retrofit_ov_conf_backup_acl as mod

        unicode_file = self.root / 'ov.conf-before-b\u1ea3n-sao-l\u01b0u-20261112.json'
        third_file = self.root / 'ov.conf-before-zzz-20261112.json'
        unicode_file.write_bytes(self.payload)
        third_file.write_bytes(self.payload)
        mod.apply_restricted_file_acl(unicode_file)
        for p in (self.sample, third_file):
            subprocess.run(['icacls', str(p), '/grant', '*S-1-1-0:(R)'],
                           capture_output=True, check=True, timeout=10)
        plan = mod.build_plan(self.root)
        by_name = {row['name']: row for row in plan['files']}
        self.assertTrue(by_name[self.sample.name]['needs_harden'])
        self.assertFalse(by_name[unicode_file.name]['needs_harden'])
        self.assertTrue(by_name[third_file.name]['needs_harden'])

        receipt = mod.apply_retrofit(self.root)
        self.assertEqual(receipt['hardened_count'], 2)
        self.assertEqual(sorted(receipt['hardened_names']), sorted([self.sample.name, third_file.name]))

    def test_plan_file_missing_or_mismatched_sddl_sha256_aborts(self):
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        plan = mod.build_plan(self.root)
        plan_path = Path(self.tmp.name) / 'sddl-plan.json'
        receipt_path = Path(self.tmp.name) / 'sddl-aborted.json'

        stripped = json.loads(json.dumps(plan))
        stripped['files'][0].pop('sddl_sha256')
        plan_path.write_text(json.dumps(stripped), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'sddl_sha256'):
            mod.apply_retrofit(self.root, receipt_path=receipt_path, plan_file=plan_path)
        aborted = json.loads(receipt_path.read_text(encoding='utf-8'))
        self.assertEqual(aborted['mode'], 'APPLY_ABORTED')
        self.assertEqual(len(aborted.get('plan_sha256', '')), 64)

        drifted = json.loads(json.dumps(plan))
        drifted['files'][0]['sddl_sha256'] = '0' * 64
        plan_path.write_text(json.dumps(drifted), encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'drift'):
            mod.apply_retrofit(self.root, receipt_path=receipt_path, plan_file=plan_path)

    def test_receipt_write_failure_warns_without_masking_error_and_cli_rejects_plan_without_apply(self):
        import io
        from contextlib import redirect_stderr
        import retrofit_ov_conf_backup_acl as mod

        subprocess.run(['icacls', str(self.sample), '/grant', '*S-1-1-0:(R)'],
                       capture_output=True, check=True, timeout=10)
        receipt_path = Path(self.tmp.name) / 'unwritable-receipt.json'
        stderr_buf = io.StringIO()
        with patch.object(mod, 'apply_restricted_file_acl', return_value=False), \
             patch.object(Path, 'write_text', side_effect=OSError('disk full')), \
             redirect_stderr(stderr_buf):
            with self.assertRaises(PermissionError):
                mod.apply_retrofit(self.root, receipt_path=receipt_path)
        self.assertIn('warning: failed to write receipt', stderr_buf.getvalue())

        with self.assertRaises(SystemExit) as ctx, redirect_stderr(io.StringIO()):
            mod.main(['--plan-file', 'x.json'])
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == '__main__':
    unittest.main()
