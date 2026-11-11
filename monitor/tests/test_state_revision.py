"""State saves refuse to overwrite revisions changed after loading."""
import copy
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class StateRevisionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='ov-state-revision-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.folder.cleanup)
        self.directory = Path(self.folder.name)
        self.target = self.directory / 'monitor.json'
        self.ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='state_revision_test')
        self.glob = self.ns['load_state'].__globals__
        self.glob.update(APP_DIR=self.directory, STATE_PATH=self.target, APP_LOG=self.directory / 'app.log')
        self.baseline = dict(watch_keys=[], spare_models=[], watch_auto_enabled=True,
                             watch_auto_migrated=True, auto_probe_enabled=False,
                             notify_on_failover=True, geometry='1020x800')
        self.original = json.dumps(self.baseline).encode('utf-8')
        self.target.write_bytes(self.original)

    def test_newer_valid_document_is_preserved_before_writer(self):
        loaded = self.ns['load_state']()
        candidate = dict(loaded, geometry='1100x800')
        newer = json.dumps(dict(self.baseline, notify_on_failover=False)).encode('utf-8')
        self.target.write_bytes(newer)
        writer = Mock()
        with patch.dict(self.glob, safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](candidate)
        writer.assert_not_called()
        self.assertEqual(self.target.read_bytes(), newer)

    def test_damage_after_load_is_preserved(self):
        for damaged in (b'{"watch_keys":[', b'\xff', b'null'):
            with self.subTest(damaged=damaged):
                self.target.write_bytes(self.original)
                loaded = self.ns['load_state']()
                self.target.write_bytes(damaged)
                writer = Mock()
                with patch.dict(self.glob, safe_atomic_write_json=writer):
                    with self.assertRaises(RuntimeError):
                        self.ns['save_state'](loaded)
                writer.assert_not_called()
                self.assertEqual(self.target.read_bytes(), damaged)
                self.assertFalse(loaded['watch_auto_enabled'])
                self.assertFalse(loaded['auto_probe_enabled'])

    def test_deleted_or_unreadable_revision_is_not_recreated(self):
        loaded = self.ns['load_state']()
        self.target.unlink()
        with self.assertRaises(RuntimeError):
            self.ns['save_state'](loaded)
        self.assertFalse(self.target.exists())
        for failure in (PermissionError, OSError, FileNotFoundError):
            with self.subTest(failure=failure):
                self.target.write_bytes(self.original)
                loaded = self.ns['load_state']()
                writer = Mock()
                with patch.object(Path, 'read_bytes', side_effect=failure('synthetic-sensitive-detail')), \
                     patch.dict(self.glob, safe_atomic_write_json=writer):
                    with self.assertRaises(RuntimeError):
                        self.ns['save_state'](loaded)
                writer.assert_not_called()
                self.assertEqual(self.target.read_bytes(), self.original)
        self.assertNotIn('synthetic-sensitive-detail', (self.directory / 'app.log').read_text(encoding='utf-8'))

    def test_missing_file_creation_conflict_is_preserved(self):
        self.target.unlink()
        loaded = self.ns['load_state']()
        self.target.write_bytes(self.original)
        with self.assertRaises(RuntimeError):
            self.ns['save_state'](loaded)
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_first_run_and_repeated_own_saves_advance_revision(self):
        self.target.unlink()
        loaded = self.ns['load_state']()
        self.ns['save_state'](loaded)
        first = loaded['_state_revision']
        loaded['geometry'] = '1200x800'
        self.ns['save_state'](loaded)
        self.assertNotEqual(loaded['_state_revision'], first)
        self.assertNotIn('_state_revision', json.loads(self.target.read_bytes()))
        self.assertEqual(json.loads(self.target.read_bytes())['geometry'], '1200x800')

    def test_stale_candidate_cannot_reuse_newer_own_save(self):
        loaded = self.ns['load_state']()
        stale = copy.deepcopy(loaded)
        loaded['geometry'] = '1200x800'
        self.ns['save_state'](loaded)
        newer = self.target.read_bytes()
        with self.assertRaises(RuntimeError):
            self.ns['save_state'](stale)
        self.assertEqual(self.target.read_bytes(), newer)
        self.ns['save_state'](loaded)

    def test_conflict_stays_locked_even_if_original_bytes_are_restored(self):
        loaded = self.ns['load_state']()
        self.target.write_bytes(b'{}')
        with self.assertRaises(RuntimeError):
            self.ns['save_state'](loaded)
        self.target.write_bytes(self.original)
        with self.assertRaises(RuntimeError):
            self.ns['save_state'](loaded)
        self.ns['save_state'](self.ns['load_state']())

    def test_raw_newline_changes_are_detected(self):
        raw = json.dumps(self.baseline, indent=2).replace('\n', '\r\n').encode('utf-8')
        self.target.write_bytes(raw)
        loaded = self.ns['load_state']()
        self.target.write_bytes(raw.replace(b'\r\n', b'\n'))
        with self.assertRaises(RuntimeError):
            self.ns['save_state'](loaded)
        self.assertEqual(self.target.read_bytes(), raw.replace(b'\r\n', b'\n'))

    def test_failed_publish_does_not_advance_revision(self):
        loaded = self.ns['load_state']()
        revision = loaded['_state_revision']
        with patch.dict(self.glob, safe_atomic_write_json=Mock(side_effect=OSError('synthetic-only'))):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        self.assertEqual(loaded['_state_revision'], revision)
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertNotIn('_state_revision_error', loaded)
        self.ns['save_state'](loaded)

    def test_unverifiable_absence_cannot_allow_first_write(self):
        self.target.unlink()
        loaded = self.ns['load_state']()
        writer = Mock()
        with patch.object(Path, 'read_bytes', side_effect=FileNotFoundError('synthetic-sensitive-detail')), \
             patch.object(Path, 'lstat', side_effect=PermissionError('synthetic-sensitive-detail')), \
             patch.dict(self.glob, safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertFalse(self.target.exists())
        self.assertFalse(loaded['watch_auto_enabled'])

    def test_raw_revision_metadata_from_disk_is_not_trusted(self):
        self.target.write_text(json.dumps(dict(self.baseline, _state_revision='forged')), encoding='utf-8')
        loaded = self.ns['load_state']()
        self.assertNotEqual(loaded['_state_revision'], 'forged')
        self.ns['save_state'](loaded)
        self.assertNotIn('_state_revision', json.loads(self.target.read_bytes()))

    def test_revision_check_happens_after_lock_acquisition(self):
        from contextlib import contextmanager
        loaded = self.ns['load_state']()
        newer = b'{}'
        @contextmanager
        def lock(_path):
            self.target.write_bytes(newer)
            yield
        writer = Mock()
        with patch.dict(self.glob, interprocess_file_lock=lock, safe_atomic_write_json=writer):
            with self.assertRaises(RuntimeError):
                self.ns['save_state'](loaded)
        writer.assert_not_called()
        self.assertEqual(self.target.read_bytes(), newer)


if __name__ == '__main__':
    unittest.main()
