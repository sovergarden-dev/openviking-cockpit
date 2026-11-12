"""Verified, restricted-ACL, no-clobber backups for ov.conf on synthetic files only."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@unittest.skipUnless(sys.platform == 'win32', 'Windows-only os.rename no-clobber and ACL checks')
class BackupOvConfTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='ov-conf-bak-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.folder.cleanup)
        self.ov_home = Path(self.folder.name) / '.openviking'
        self.app_dir = self.ov_home / 'monitor'
        self.app_dir.mkdir(parents=True)
        self.conf_path = self.ov_home / 'ov.conf'
        self.backups_dir = self.ov_home / 'backups'
        self.app_log = self.app_dir / 'app.log'
        self.ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='backup_ov_conf_test')
        self.glob = self.ns['backup_ov_conf'].__globals__
        self.glob.update(
            OV_HOME=self.ov_home,
            APP_DIR=self.app_dir,
            CONF_PATH=self.conf_path,
            APP_LOG=self.app_log,
        )
        self.baseline = {
            'vlm': {
                'model': 'fixture/primary',
                'api_base': 'https://fixture.invalid/v1',
                'api_key': '${SYNTHETIC_PRIMARY_KEY}',
                'credentials': [
                    {
                        'id': 'slot-0',
                        'model': 'fixture/primary',
                        'api_base': 'https://fixture.invalid/v1',
                        'api_key': '${SYNTHETIC_PRIMARY_KEY}',
                    }
                ],
            }
        }
        self.original = (json.dumps(self.baseline, indent=2).replace('\n', '\r\n') + '\r\n').encode('utf-8')
        self.conf_path.write_bytes(self.original)

    def test_backup_preserves_exact_crlf_and_env_refs(self):
        backup = self.ns['backup_ov_conf']('slot-edit')
        self.assertTrue(backup.is_relative_to(Path(self.folder.name)))
        self.assertEqual(backup.parent.resolve(), self.backups_dir.resolve())
        self.assertTrue(backup.name.startswith('ov.conf-before-slot-edit-'))
        self.assertTrue(backup.name.endswith('.json'))
        self.assertEqual(backup.read_bytes(), self.original)
        self.assertIn(b'${SYNTHETIC_PRIMARY_KEY}', backup.read_bytes())
        self.assertEqual(list(self.backups_dir.iterdir()), [backup])

    def test_same_second_calls_do_not_clobber_each_other(self):
        second = json.loads(self.original.decode('utf-8'))
        second['vlm']['model'] = 'fixture/second'
        second_bytes = (json.dumps(second, indent=2).replace('\n', '\r\n') + '\r\n').encode('utf-8')
        with patch.dict(self.glob, _backup_stamp=lambda: '20261112-030000'):
            first_path = self.ns['backup_ov_conf']('slot-edit')
            self.conf_path.write_bytes(second_bytes)
            second_path = self.ns['backup_ov_conf']('slot-edit')
        self.assertNotEqual(first_path, second_path)
        self.assertEqual(first_path.read_bytes(), self.original)
        self.assertEqual(second_path.read_bytes(), second_bytes)

    def test_same_second_identical_content_never_clobbers_existing_file(self):
        with patch.dict(self.glob, _backup_stamp=lambda: '20261112-030000'):
            first_path = self.ns['backup_ov_conf']('slot-edit')
            first_stat = first_path.stat()
            first_sha = hashlib.sha256(first_path.read_bytes()).hexdigest()
            second_path = self.ns['backup_ov_conf']('slot-edit')
        self.assertNotEqual(first_path, second_path)
        self.assertTrue(second_path.stem.endswith('-1'))
        after_stat = first_path.stat()
        self.assertEqual(hashlib.sha256(first_path.read_bytes()).hexdigest(), first_sha)
        self.assertEqual(after_stat.st_size, first_stat.st_size)
        self.assertEqual(after_stat.st_mtime_ns, first_stat.st_mtime_ns)
        self.assertEqual(first_path.read_bytes(), self.original)
        self.assertEqual(second_path.read_bytes(), self.original)

    def test_preexisting_target_filename_is_never_overwritten(self):
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        digest8 = hashlib.sha256(self.original).hexdigest()[:8]
        sentinels = (
            'ov.conf-before-slot-edit-20261112-030000.json',
            f'ov.conf-before-slot-edit-20261112-030000-{digest8}.json',
            f'ov.conf-before-slot-edit-20261112-030000-{digest8}-1.json',
        )
        for candidate_name in sentinels:
            (self.backups_dir / candidate_name).write_bytes(b'sentinel-keep-me')
        with patch.dict(self.glob, _backup_stamp=lambda: '20261112-030000'):
            backup = self.ns['backup_ov_conf']('slot-edit')
        self.assertNotIn(backup.name, sentinels)
        for candidate_name in sentinels:
            self.assertEqual((self.backups_dir / candidate_name).read_bytes(), b'sentinel-keep-me')
        self.assertEqual(backup.read_bytes(), self.original)

    def test_reason_is_sanitized_against_path_traversal(self):
        for raw_reason in ('../../escape', 'a/b\\c:d', '', '   ', '..\\..\\outside'):
            with self.subTest(reason=raw_reason):
                backup = self.ns['backup_ov_conf'](raw_reason)
                self.assertEqual(backup.parent.resolve(), self.backups_dir.resolve())
                self.assertTrue(backup.name.startswith('ov.conf-before-'))
                self.assertNotIn('..', backup.name)
                self.assertNotIn('/', backup.name)
                self.assertNotIn('\\', backup.name)
                self.assertNotIn(':', backup.name)
                self.assertEqual(backup.read_bytes(), self.original)

    def test_acl_is_protected_and_restricted_on_backup_file(self):
        backup = self.ns['backup_ov_conf']('slot-edit')
        script = (
            "$ErrorActionPreference='Stop'; "
            "$p = ConvertFrom-Json ([Console]::In.ReadToEnd()); "
            "$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
            "$expected = \"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)\"; "
            "$acl = Get-Acl -LiteralPath $p; "
            "if (-not $acl.AreAccessRulesProtected) { throw \"Unprotected ACL on $p\" }; "
            "$sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); "
            "if (($sddl -replace '^D:PAI','D:P') -ne $expected) { throw \"Unexpected DACL: $sddl\" }"
        )
        res = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
            input=json.dumps(str(backup)),
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_acl_failure_blocks_backup_and_leaves_no_partial_file(self):
        with patch.dict(self.glob, apply_restricted_file_acl=Mock(return_value=False)):
            with self.assertRaises((PermissionError, OSError)):
                self.ns['backup_ov_conf']('slot-edit')
        if self.backups_dir.exists():
            self.assertEqual(list(self.backups_dir.iterdir()), [])

    def test_fsync_failure_cleans_up_and_blocks_checked_write(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        with patch.object(os, 'fsync', side_effect=OSError('synthetic-secret-detail')), \
             patch.dict(self.glob, validate_conf_targets=Mock(return_value=[]), safe_atomic_write_json=writer):
            with self.assertRaises(OSError):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertEqual(self.conf_path.read_bytes(), self.original)
        if self.backups_dir.exists():
            self.assertEqual(list(self.backups_dir.iterdir()), [])
        if self.app_log.exists():
            self.assertNotIn('synthetic-secret-detail', self.app_log.read_text(encoding='utf-8'))

    def test_readback_mismatch_removes_backup_and_blocks_checked_write(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        real_read = Path.read_bytes

        def corrupt_backup_readback(path_obj):
            if path_obj.parent == self.backups_dir:
                return b'{}'
            return real_read(path_obj)

        with patch.object(Path, 'read_bytes', autospec=True, side_effect=corrupt_backup_readback), \
             patch.dict(self.glob, validate_conf_targets=Mock(return_value=[]), safe_atomic_write_json=writer):
            with self.assertRaises(OSError):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertEqual(self.conf_path.read_bytes(), self.original)
        if self.backups_dir.exists():
            self.assertEqual(list(self.backups_dir.iterdir()), [])

    def test_reparse_point_in_backups_dir_is_rejected_before_write(self):
        outside = Path(self.folder.name) / 'outside'
        outside.mkdir()
        res = subprocess.run(
            ['cmd.exe', '/d', '/c', 'mklink', '/J', str(self.backups_dir), str(outside)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        try:
            with self.assertRaises((ValueError, OSError)):
                self.ns['backup_ov_conf']('slot-edit')
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            os.rmdir(self.backups_dir)

    def test_empty_conf_is_rejected_without_creating_backup(self):
        self.conf_path.write_bytes(b'')
        with self.assertRaises(ValueError):
            self.ns['backup_ov_conf']('slot-edit')
        if self.backups_dir.exists():
            self.assertEqual(list(self.backups_dir.iterdir()), [])

    def test_dest_acl_failure_after_publish_removes_published_file_and_temp(self):
        with patch.dict(
            self.glob,
            apply_restricted_file_acl=Mock(side_effect=lambda p: not Path(p).name.startswith('ov.conf-before-')),
        ):
            with self.assertRaises(PermissionError):
                self.ns['backup_ov_conf']('slot-edit')
        self.assertEqual(list(self.backups_dir.iterdir()), [])

    def test_reparse_point_in_conf_path_is_rejected_before_read(self):
        outside_conf = Path(self.folder.name) / 'outside.conf'
        outside_conf.write_bytes(self.original)
        self.conf_path.unlink()
        res = subprocess.run(
            ['cmd.exe', '/d', '/c', 'mklink', str(self.conf_path), str(outside_conf)],
            capture_output=True, text=True, timeout=10,
        )
        if res.returncode != 0:
            self.skipTest('symlink creation privilege unavailable in this environment')
        with self.assertRaises((ValueError, OSError)):
            self.ns['backup_ov_conf']('slot-edit')
        self.assertFalse(self.backups_dir.exists())

    def test_reparse_attribute_on_conf_path_is_rejected_before_read(self):
        import types
        fake_stat = types.SimpleNamespace(st_mode=0o100644, st_file_attributes=0x400)
        real_lstat = Path.lstat

        def fake_lstat(path_obj):
            if path_obj == self.conf_path:
                return fake_stat
            return real_lstat(path_obj)

        with patch.object(Path, 'lstat', autospec=True, side_effect=fake_lstat):
            with self.assertRaisesRegex(ValueError, 'reparse point'):
                self.ns['backup_ov_conf']('slot-edit')
        self.assertFalse(self.backups_dir.exists())

    def test_checked_writer_happy_path_creates_verified_acl_backup(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/new-primary'
        digest = self.ns['_conf_digest'](self.baseline)
        with patch.dict(self.glob, validate_conf_targets=Mock(return_value=[])):
            backup = self.ns['write_ov_conf_checked'](
                candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
            )
        self.assertTrue(backup.is_file())
        self.assertEqual(backup.read_bytes(), self.original)
        self.assertEqual(json.loads(self.conf_path.read_text(encoding='utf-8')), candidate)

    def test_log_app_failure_does_not_mask_backup_error_or_leave_dest(self):
        with patch.dict(
            self.glob,
            apply_restricted_file_acl=Mock(side_effect=lambda p: not Path(p).name.startswith('ov.conf-before-')),
            log_app=Mock(side_effect=OSError('log full')),
        ):
            with self.assertRaises(PermissionError):
                self.ns['backup_ov_conf']('slot-edit')
        self.assertEqual(list(self.backups_dir.iterdir()), [])

    def test_rename_oserror_fails_closed_without_artifacts(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        with patch.object(os, 'rename', side_effect=OSError('rename failed')), \
             patch.dict(self.glob, validate_conf_targets=Mock(return_value=[]), safe_atomic_write_json=writer):
            with self.assertRaises(OSError):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertEqual(self.conf_path.read_bytes(), self.original)
        self.assertEqual(list(self.backups_dir.iterdir()), [])

    def test_backup_digest_drift_blocks_checked_write_and_preserves_artifact(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        drifted = json.loads(self.original.decode('utf-8'))
        drifted['vlm']['model'] = 'fixture/external-edit'
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        drifted_bak = self.backups_dir / 'ov.conf-before-slot-edit-20261112-030000-deadbeef.json'

        def make_drifted_backup(_reason):
            drifted_bak.write_text(json.dumps(drifted), encoding='utf-8')
            return drifted_bak

        with patch.dict(self.glob,
                        backup_ov_conf=make_drifted_backup,
                        validate_conf_targets=Mock(return_value=[]),
                        safe_atomic_write_json=writer):
            with self.assertRaisesRegex(RuntimeError, 'changed during backup'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        rejected = drifted_bak.with_name(drifted_bak.stem + '.REJECTED.json')
        self.assertFalse(drifted_bak.exists())
        self.assertTrue(rejected.exists())
        self.assertEqual(json.loads(rejected.read_text(encoding='utf-8')), drifted)
        self.assertEqual(self.conf_path.read_bytes(), self.original)

    def test_external_change_after_backup_blocks_write(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        real_backup = self.ns['backup_ov_conf']
        external = json.loads(self.original.decode('utf-8'))
        external['vlm']['model'] = 'fixture/post-backup-external'
        external_bytes = json.dumps(external).encode('utf-8')

        def backup_then_external_edit(reason):
            bak = real_backup(reason)
            self.conf_path.write_bytes(external_bytes)
            return bak

        with patch.dict(
            self.glob,
            backup_ov_conf=backup_then_external_edit,
            validate_conf_targets=Mock(return_value=[]),
            safe_atomic_write_json=writer,
        ):
            with self.assertRaisesRegex(RuntimeError, 'changed after backup'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertEqual(self.conf_path.read_bytes(), external_bytes)

    def test_post_backup_unreadable_conf_blocks_write(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        real_backup = self.ns['backup_ov_conf']

        def backup_then_break_read(reason):
            bak = real_backup(reason)
            self.conf_path.write_bytes(b'\xff')
            return bak

        with patch.dict(
            self.glob,
            backup_ov_conf=backup_then_break_read,
            validate_conf_targets=Mock(return_value=[]),
            safe_atomic_write_json=writer,
        ):
            with self.assertRaisesRegex(RuntimeError, 'current config not verifiable after backup'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertEqual(self.conf_path.read_bytes(), b'\xff')
        self.assertEqual(len(list(self.backups_dir.glob('ov.conf-before-slot-edit-*.json'))), 1)
        self.assertEqual(len(list(self.backups_dir.glob('*.REJECTED*.json'))), 0)

    def test_post_backup_valid_conf_drift_blocks_write_and_keeps_verified_backup(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        external = json.loads(self.original.decode('utf-8'))
        external['vlm']['model'] = 'fixture/external-after-backup'
        external_bytes = json.dumps(external).encode('utf-8')
        writer = Mock()
        real_backup = self.ns['backup_ov_conf']

        def backup_then_external_valid_write(reason):
            bak = real_backup(reason)
            self.conf_path.write_bytes(external_bytes)
            return bak

        with patch.dict(
            self.glob,
            backup_ov_conf=backup_then_external_valid_write,
            validate_conf_targets=Mock(return_value=[]),
            safe_atomic_write_json=writer,
        ):
            with self.assertRaisesRegex(RuntimeError, 'changed after backup'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertEqual(self.conf_path.read_bytes(), external_bytes)
        kept = list(self.backups_dir.glob('ov.conf-before-slot-edit-*.json'))
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].read_bytes(), self.original)
        self.assertEqual(len(list(self.backups_dir.glob('*.REJECTED*.json'))), 0)

    def test_unparseable_backup_blocks_checked_write_and_preserves_artifact(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        bad_bak = self.backups_dir / 'ov.conf-before-slot-edit-20261112-030000-bad00000.json'

        def make_bad_backup(_reason):
            bad_bak.write_bytes(b'{')
            return bad_bak

        with patch.dict(self.glob,
                        backup_ov_conf=make_bad_backup,
                        validate_conf_targets=Mock(return_value=[]),
                        safe_atomic_write_json=writer):
            with self.assertRaisesRegex(RuntimeError, 'backup artifact not verifiable'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        rejected = bad_bak.with_name(bad_bak.stem + '.REJECTED.json')
        self.assertFalse(bad_bak.exists())
        self.assertTrue(rejected.exists())
        self.assertEqual(rejected.read_bytes(), b'{')
        self.assertEqual(self.conf_path.read_bytes(), self.original)

    def test_stale_staging_tmp_older_than_one_hour_is_swept_while_fresh_stays(self):
        import time
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        stale_tmp = self.backups_dir / '.ov-conf-bak-stale.tmp'
        fresh_tmp = self.backups_dir / '.ov-conf-bak-fresh.tmp'
        unrelated = self.backups_dir / '.other.tmp'
        for p in (stale_tmp, fresh_tmp, unrelated):
            p.write_bytes(b'sentinel')
        old_ts = time.time() - 7200
        os.utime(stale_tmp, (old_ts, old_ts))
        backup = self.ns['backup_ov_conf']('slot-edit')
        self.assertTrue(backup.is_file())
        self.assertFalse(stale_tmp.exists())
        self.assertTrue(fresh_tmp.exists())
        self.assertTrue(unrelated.exists())

    def test_write_failure_preserves_verified_backup_and_original_conf(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        with patch.dict(self.glob,
                        validate_conf_targets=Mock(return_value=[]),
                        safe_atomic_write_json=Mock(side_effect=OSError('write boom'))):
            with self.assertRaises(OSError):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        self.assertEqual(self.conf_path.read_bytes(), self.original)
        created = list(self.backups_dir.glob('ov.conf-before-slot-edit-*.json'))
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].read_bytes(), self.original)

    def test_advisory_mismatch_blocks_before_backup_and_write(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        with patch.dict(
            self.glob,
            validate_conf_targets=Mock(return_value=[{'slot': 1, 'level': 3, 'model': 'm', 'why': 'cond'}]),
            safe_atomic_write_json=writer,
        ):
            with self.assertRaisesRegex(RuntimeError, 'Admission result changed'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertFalse(self.backups_dir.exists())
        self.assertEqual(self.conf_path.read_bytes(), self.original)

    def test_missing_conf_raises_without_creating_backup(self):
        self.conf_path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.ns['backup_ov_conf']('slot-edit')
        if self.backups_dir.exists():
            self.assertEqual(list(self.backups_dir.iterdir()), [])

    def test_rejected_backup_quarantine_uses_collision_suffix_and_retains_acl(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        real_backup = self.ns['backup_ov_conf']
        drifted = json.loads(self.original.decode('utf-8'))
        drifted['vlm']['model'] = 'fixture/external-before-backup'
        drifted_bytes = json.dumps(drifted).encode('utf-8')
        created_paths = []

        def swap_conf_and_backup(reason):
            self.conf_path.write_bytes(drifted_bytes)
            bak = real_backup(reason)
            created_paths.append(bak)
            return bak

        with patch.dict(self.glob, _backup_stamp=lambda: '20261112-030000',
                        backup_ov_conf=swap_conf_and_backup,
                        validate_conf_targets=Mock(return_value=[]),
                        safe_atomic_write_json=Mock()):
            with self.assertRaisesRegex(RuntimeError, 'changed during backup'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        first_rejected = created_paths[0].with_name(f'{created_paths[0].stem}.REJECTED.json')
        self.assertTrue(first_rejected.is_file())
        self.assertFalse(created_paths[0].exists())
        script = (
            "$ErrorActionPreference='Stop'; "
            "$p = ConvertFrom-Json ([Console]::In.ReadToEnd()); "
            "$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
            "$expected = \"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)\"; "
            "$acl = Get-Acl -LiteralPath $p; "
            "if (-not $acl.AreAccessRulesProtected) { throw 'Unprotected ACL on rejected backup' }; "
            "$sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); "
            "if (($sddl -replace '^D:PAI','D:P') -ne $expected) { throw \"Unexpected DACL: $sddl\" }"
        )
        res = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
            input=json.dumps(str(first_rejected)),
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        # Second rejection of the same target name must suffix -1 instead of keeping the original name
        self.conf_path.write_bytes(self.original)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        dup = self.backups_dir / created_paths[0].name
        dup.write_bytes(drifted_bytes)
        with patch.dict(self.glob, backup_ov_conf=lambda _r: dup,
                        validate_conf_targets=Mock(return_value=[]),
                        safe_atomic_write_json=Mock()):
            with self.assertRaisesRegex(RuntimeError, 'changed during backup'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        self.assertFalse(dup.exists())
        self.assertTrue(created_paths[0].with_name(f'{created_paths[0].stem}.REJECTED-1.json').is_file())

    def test_quarantine_failure_logs_quarantine_failed_and_blocks_write(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        logs = []
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        bad_bak = self.backups_dir / 'ov.conf-before-slot-edit-20261112-030000-bad00001.json'
        bad_bak.write_bytes(b'{')

        with patch.dict(self.glob, backup_ov_conf=lambda _r: bad_bak,
                        validate_conf_targets=Mock(return_value=[]),
                        safe_atomic_write_json=writer,
                        log_app=logs.append), \
                patch('os.rename', side_effect=OSError('locked')):
            with self.assertRaisesRegex(RuntimeError, 'backup artifact not verifiable'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertTrue(bad_bak.exists())
        self.assertTrue(any(f'quarantine_failed={bad_bak.name}' in entry for entry in logs), logs)

    def test_quarantine_helper_rejects_non_windows_and_checked_write_logs_fallback(self):
        candidate = json.loads(self.original.decode('utf-8'))
        candidate['vlm']['model'] = 'fixture/changed'
        digest = self.ns['_conf_digest'](self.baseline)
        writer = Mock()
        logs = []
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        bad_bak = self.backups_dir / 'ov.conf-before-slot-edit-20261112-030000-bad00002.json'
        bad_bak.write_bytes(b'{')

        with patch.object(self.glob['os'], 'name', 'posix'):
            with self.assertRaises(OSError):
                self.ns['_quarantine_rejected_backup'](bad_bak)
        with patch.dict(self.glob, backup_ov_conf=lambda _r: bad_bak,
                        _quarantine_rejected_backup=Mock(side_effect=OSError('non-nt')),
                        validate_conf_targets=Mock(return_value=[]),
                        safe_atomic_write_json=writer,
                        log_app=logs.append):
            with self.assertRaisesRegex(RuntimeError, 'backup artifact not verifiable'):
                self.ns['write_ov_conf_checked'](
                    candidate, digest, reason='slot-edit', before=self.baseline, expected_advisories=[]
                )
        writer.assert_not_called()
        self.assertTrue(any(f'quarantine_failed={bad_bak.name}' in entry for entry in logs), logs)


class BackupOvConfStaticTests(unittest.TestCase):
    def test_no_production_caller_uses_unchecked_write_ov_conf(self):
        import ast
        tree = ast.parse((ROOT / 'openviking-monitor.pyw').read_text(encoding='utf-8'))
        calls = [
            node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'write_ov_conf'
        ]
        self.assertEqual(calls, [], f'unchecked write_ov_conf called in production at lines {calls}')

    def test_backup_helpers_never_use_clobbering_replace_or_move(self):
        import ast
        tree = ast.parse((ROOT / 'openviking-monitor.pyw').read_text(encoding='utf-8'))
        found = set()
        for fn in tree.body:
            if isinstance(fn, ast.FunctionDef) and fn.name in {'backup_ov_conf', '_quarantine_rejected_backup'}:
                found.add(fn.name)
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        if node.func.attr in {'replace', 'move'}:
                            self.fail(f'{fn.name} must not call .{node.func.attr}() at line {node.lineno}')
        self.assertEqual(found, {'backup_ov_conf', '_quarantine_rejected_backup'})


if __name__ == '__main__':
    unittest.main()
