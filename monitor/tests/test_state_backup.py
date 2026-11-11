"""Verified pre-change snapshots and same-user isolated recovery; no live state."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class StateBackupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='ov-state-backup-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.folder.cleanup)
        self.directory = Path(self.folder.name) / 'monitor'
        self.directory.mkdir()
        self.target = self.directory / 'monitor.json'
        self.backups = self.directory.parent / 'backups' / 'monitor-state'
        self.ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='state_backup_test')
        self.glob = self.ns['load_state'].__globals__
        self.glob.update(APP_DIR=self.directory, STATE_PATH=self.target, APP_LOG=self.directory / 'app.log')
        protected = self.ns['dpapi_protect']('synthetic-backup-fixture')
        data = dict(watch_keys=[dict(id='fixture', alias='Fixture', api_key=protected)],
                    spare_models=[], watch_auto_enabled=False, watch_auto_migrated=True,
                    auto_probe_enabled=False, geometry='1020x800')
        self.original = (json.dumps(data, ensure_ascii=False, indent=2).replace('\n', '\r\n') + '\r\n').encode('utf-8')
        self.target.write_bytes(self.original)
        self.digest = hashlib.sha256(self.original).hexdigest()
        self.snapshot = self.backups / self.digest

    def test_changed_save_preserves_verified_original_bytes(self):
        loaded = self.ns['load_state']()
        loaded['geometry'] = '1100x800'
        self.ns['save_state'](loaded)
        self.assertTrue((self.snapshot / 'monitor.json').is_file(), 'changed save has no pre-change backup')
        self.assertEqual((self.snapshot / 'monitor.json').read_bytes(), self.original)
        manifest = json.loads((self.snapshot / 'manifest.json').read_bytes())
        self.assertEqual(manifest['sha256'], self.digest)
        self.assertEqual(manifest['byte_count'], len(self.original))
        self.assertTrue(manifest['created_utc'].endswith('+00:00'))
        self.assertNotIn(b'synthetic-backup-fixture', (self.snapshot / 'monitor.json').read_bytes())
        self.assertEqual(json.loads(self.target.read_bytes())['geometry'], '1100x800')

    def test_identical_save_does_not_publish_or_create_another_backup(self):
        from unittest.mock import Mock, patch
        loaded = self.ns['load_state']()
        self.ns['save_state'](loaded)
        loaded = self.ns['load_state']()
        before = self.target.stat().st_mtime_ns
        snapshots = sorted(p.name for p in self.backups.iterdir())
        writer = Mock()
        with patch.dict(self.glob, safe_atomic_write_json=writer):
            self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertEqual(self.target.stat().st_mtime_ns, before)
        self.assertEqual(sorted(p.name for p in self.backups.iterdir()), snapshots)

    def test_backup_failure_never_reaches_state_writer(self):
        from unittest.mock import Mock, patch
        loaded = self.ns['load_state']()
        revision = loaded['_state_revision']
        loaded['geometry'] = '1100x800'
        writer = Mock()
        with patch.dict(self.glob, apply_restricted_file_acl=Mock(return_value=False),
                        safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(loaded['_state_revision'], revision)
        self.assertEqual(list(self.backups.iterdir()), [])

    def test_existing_snapshot_is_reused_only_with_matching_manifest(self):
        first = self.ns['backup_state'](self.original)
        before = (first / 'manifest.json').stat().st_mtime_ns
        self.assertEqual(self.ns['backup_state'](self.original), first)
        self.assertEqual((first / 'manifest.json').stat().st_mtime_ns, before)
        (first / 'manifest.json').write_text('{}', encoding='utf-8')
        loaded = self.ns['load_state']()
        loaded['geometry'] = '1200x800'
        with self.assertRaises(RuntimeError):
            self.ns['save_state'](loaded)
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_existing_snapshot_fails_closed_if_acl_cannot_be_restricted(self):
        from unittest.mock import Mock, patch
        self.ns['backup_state'](self.original)
        loaded = self.ns['load_state']()
        loaded['geometry'] = '1100x800'
        writer = Mock()
        with patch.dict(self.glob, apply_restricted_file_acl=Mock(return_value=False),
                        safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_reused_snapshot_removes_extra_explicit_acl_grants(self):
        import subprocess
        first = self.ns['backup_state'](self.original)
        for path in (first, first / 'monitor.json', first / 'manifest.json'):
            subprocess.run(['icacls', str(path), '/grant', '*S-1-1-0:(R)'],
                           capture_output=True, check=True, timeout=10)
        self.ns['backup_state'](self.original)
        script = "$paths = ConvertFrom-Json ([Console]::In.ReadToEnd()); foreach ($p in $paths) { $a = Get-Acl -LiteralPath $p; $a.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access) }"
        result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', script],
                                input=json.dumps([str(first), str(first / 'monitor.json'), str(first / 'manifest.json')]),
                                capture_output=True, text=True, check=True, timeout=20)
        self.assertNotIn(';;;WD)', result.stdout, 'backup retained explicit Everyone access')
        self.assertTrue(all(line.startswith('D:P') for line in result.stdout.splitlines() if line))

    def test_corrupt_snapshot_bytes_block_state_write(self):
        from unittest.mock import Mock, patch
        self.ns['backup_state'](self.original)
        (self.snapshot / 'monitor.json').write_bytes(b'{}')
        loaded = self.ns['load_state']()
        loaded['geometry'] = '1100x800'
        writer = Mock()
        with patch.dict(self.glob, safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_invalid_prechange_document_is_not_archived(self):
        for document in (b'null', b'\xff', b'{', b'{"watch_keys":{}}', b'{"watch_keys":false}',
                         b'{"watch_keys":[null]}', b'{"spare_models":[null]}',
                         b'{"spare_models":[{"api_key":123}]}'):
            with self.subTest(document_type=hashlib.sha256(document).hexdigest()[:8]):
                with self.assertRaises((ValueError, UnicodeError)):
                    self.ns['backup_state'](document)
        self.assertFalse(self.backups.exists())

    def test_snapshot_root_junction_is_rejected_before_any_write(self):
        import subprocess
        outside = self.directory.parent / 'outside'
        outside.mkdir()
        self.backups.parent.mkdir()
        result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(self.backups), str(outside)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            with self.assertRaises((ValueError, OSError)):
                self.ns['backup_state'](self.original)
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            os.rmdir(self.backups)

    def test_revision_drift_during_backup_blocks_publication(self):
        from unittest.mock import Mock, patch
        loaded = self.ns['load_state']()
        loaded['geometry'] = '1100x800'
        writer = Mock()
        newer = b'{"newer":"fixture"}'
        def backup_then_drift(_raw):
            self.target.write_bytes(newer)
        with patch.dict(self.glob, backup_state=backup_then_drift, safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertEqual(self.target.read_bytes(), newer)
        self.assertTrue(loaded.get('_state_revision_error'))

    def test_restore_requires_explicit_file_replacement_and_reopen(self):
        self.ns['save_state'](dict(self.ns['load_state'](), geometry='1100x800'))
        snapshot_bytes = (self.snapshot / 'monitor.json').read_bytes()
        self.target.write_bytes(b'{"watch_keys":[')
        locked = self.ns['load_state']()
        self.assertTrue(locked.get('_state_load_error'))
        self.target.write_bytes(snapshot_bytes)
        with self.assertRaises(RuntimeError):
            self.ns['save_state'](locked)
        reopened = self.ns['load_state']()
        self.assertFalse(reopened.get('_state_load_error'))
        self.assertEqual(reopened['watch_keys'][0]['api_key'], 'synthetic-backup-fixture')
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(reopened['_state_revision'], self.digest)

    def test_fsync_failure_keeps_original_and_removes_pending_snapshot(self):
        from unittest.mock import Mock, patch
        loaded = self.ns['load_state']()
        loaded['geometry'] = '1100x800'
        writer = Mock()
        with patch.object(os, 'fsync', side_effect=OSError('synthetic-sensitive-detail')), \
             patch.dict(self.glob, safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(list(self.backups.iterdir()), [])
        self.assertNotIn('synthetic-sensitive-detail', (self.directory / 'app.log').read_text(encoding='utf-8'))

    def test_locked_ciphertext_is_backed_up_without_decryption(self):
        from unittest.mock import Mock, patch
        document = json.loads(self.original)
        document['watch_keys'][0]['api_key'] = 'dpapi:synthetic-invalid-fixture'
        raw = json.dumps(document).encode('utf-8')
        self.target.write_bytes(raw)
        loaded = self.ns['load_state']()
        self.assertTrue(loaded['watch_keys'][0]['_dpapi_locked'])
        loaded['geometry'] = '1100x800'
        decrypt = Mock(side_effect=AssertionError('backup must not decrypt'))
        with patch.dict(self.glob, dpapi_unprotect_strict=decrypt):
            self.ns['save_state'](loaded)
        decrypt.assert_not_called()
        saved = self.backups / hashlib.sha256(raw).hexdigest() / 'monitor.json'
        self.assertEqual(saved.read_bytes(), raw)
        self.assertEqual(json.loads(self.target.read_bytes())['watch_keys'][0]['api_key'],
                         document['watch_keys'][0]['api_key'])

    def test_new_profile_needs_no_fictional_prechange_backup(self):
        self.target.unlink()
        self.ns['save_state'](self.ns['load_state']())
        self.assertTrue(self.target.is_file())
        self.assertFalse(self.backups.exists())

    def test_deduplication_rejects_missing_or_invalid_creation_timestamp(self):
        first = self.ns['backup_state'](self.original)
        manifest = json.loads((first / 'manifest.json').read_bytes())
        for timestamp in (None, 'invalid', '2026-01-01T00:00:00'):
            with self.subTest(timestamp=timestamp):
                changed = dict(manifest, created_utc=timestamp)
                (first / 'manifest.json').write_text(json.dumps(changed), encoding='utf-8')
                with self.assertRaises((ValueError, OSError)):
                    self.ns['backup_state'](self.original)

    def test_repeated_save_of_new_credentials_does_not_rotate_ciphertext(self):
        loaded = self.ns['load_state']()
        loaded['watch_keys'][0]['api_key'] = 'synthetic-new-backup-key'
        self.ns['save_state'](loaded)
        before = self.target.read_bytes()
        snapshots = sorted(p.name for p in self.backups.iterdir())
        self.ns['save_state'](loaded)
        self.assertEqual(self.target.read_bytes(), before, 'unchanged key was re-encrypted on repeated save')
        self.assertEqual(sorted(p.name for p in self.backups.iterdir()), snapshots)
        self.assertNotIn('_state_key_cache', json.loads(before))

    def test_disk_key_cache_cannot_supply_a_forged_cipher(self):
        document = json.loads(self.original)
        document['_state_key_cache'] = {'forged': 'dpapi:synthetic-invalid'}
        self.target.write_text(json.dumps(document), encoding='utf-8')
        loaded = self.ns['load_state']()
        self.assertNotIn('_state_key_cache', loaded)
        self.assertEqual(loaded['watch_keys'][0]['api_key'], 'synthetic-backup-fixture')

    def test_failed_publication_does_not_publish_key_cache(self):
        import copy
        from unittest.mock import Mock, patch
        loaded = self.ns['load_state']()
        loaded['watch_keys'][0]['api_key'] = 'synthetic-edited-key'
        before = copy.deepcopy(loaded)
        with patch.dict(self.glob, safe_atomic_write_json=Mock(side_effect=OSError('synthetic-write-error'))):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        self.assertEqual(loaded, before)
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_unreadable_revision_after_backup_locks_state(self):
        from unittest.mock import Mock, patch
        loaded = self.ns['load_state']()
        loaded['geometry'] = '1100x800'
        writer = Mock()
        with patch.dict(self.glob, _state_disk_revision=Mock(side_effect=[self.digest, PermissionError('synthetic')]),
                        backup_state=Mock(), safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertTrue(loaded.get('_state_revision_error'), 'post-backup read failure did not lock stale state')


if __name__ == '__main__':
    unittest.main()
