import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DeploymentSafetyTests(unittest.TestCase):
    def test_default_deploy_is_plan_only(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            destination = Path(directory) / 'monitor'
            destination.mkdir()
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                 str(ROOT / 'scripts/deploy_to_live.ps1'), '-LiveDir', str(destination)],
                capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(destination.iterdir()), [], 'Default deployment must only show a plan, not write live files')

    def test_watch_modules_are_required_deploy_artifacts(self):
        module = self.load_sync()
        self.assertTrue({'watch_keys.py', 'watch_panel.py'} <= set(module.CORE_FILES),
                        'New watch UI dependencies are missing from deployment')

    def load_sync(self):
        path = ROOT / 'scripts/monitor_sync.py'
        self.assertTrue(path.is_file(), 'Transactional synchronization helper is missing')
        spec = importlib.util.spec_from_file_location('monitor_sync', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_transaction_rolls_back_after_second_publish_failure(self):
        from unittest.mock import patch
        module = self.load_sync()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            base = Path(directory)
            source, dest = base/'source', base/'dest'
            source.mkdir(); dest.mkdir()
            for name in module.CORE_FILES:
                (source/name).write_bytes(b'new source')
                (dest/name).write_bytes(b'old source')
            (dest/'monitor.json').write_text('protected', encoding='utf-8')
            plan = module.make_plan(source, dest)
            publish = module._publish
            calls = [0]
            def fail_second(path, data):
                if path.is_relative_to(dest):
                    calls[0] += 1
                    if calls[0] == 2:
                        raise OSError('injected failure')
                return publish(path, data)
            with patch.object(module, '_publish', side_effect=fail_second):
                with self.assertRaisesRegex(RuntimeError, 'rolled back'):
                    module.apply_plan(plan, base/'backups', check_running=False)
            self.assertTrue(all((dest/n).read_bytes()==b'old source' for n in module.CORE_FILES))
            self.assertEqual((dest/'monitor.json').read_text(), 'protected')

    def test_monitor_text_plan_ignores_line_ending_only_drift(self):
        module = self.load_sync()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            base = Path(directory)
            source, dest = base/'source', base/'dest'
            source.mkdir(); dest.mkdir()
            for name in module.CORE_FILES:
                payload = b'line one\r\nline two\r\n' if name.endswith(('.py', '.pyw')) else b'opaque binary\x00\xff'
                (source/name).write_bytes(payload)
                (dest/name).write_bytes(payload.replace(b'\r\n', b'\n') if name.endswith(('.py', '.pyw')) else payload)
            plan = module.make_plan(source, dest)
            self.assertEqual(plan['changed_count'], 0)
            self.assertTrue(all(not row['changed'] for row in plan['files']))

    def test_plan_rejects_destination_drift(self):
        module = self.load_sync()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            base=Path(directory);source=base/'source';dest=base/'dest'
            source.mkdir();dest.mkdir()
            for name in module.CORE_FILES:
                (source/name).write_bytes(b'new')
                (dest/name).write_bytes(b'old')
            plan=module.make_plan(source,dest)
            changed=dest/module.CORE_FILES[0]
            changed.write_bytes(b'concurrent edit')
            with self.assertRaisesRegex(RuntimeError,'drift'):
                module.apply_plan(plan,base/'backups',check_running=False)
            self.assertEqual(changed.read_bytes(), b'concurrent edit')
            self.assertFalse((base/'backups').exists())

    def fixture(self, base, module):
        source,dest=base/'source',base/'dest'
        source.mkdir();dest.mkdir()
        for name in module.CORE_FILES:
            (source/name).write_bytes(b'new source')
            (dest/name).write_bytes(b'old source')
        return source,dest

    def test_apply_verified_and_idempotent_secrets_untouched(self):
        module=self.load_sync()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            base=Path(directory);source,dest=self.fixture(base,module)
            (dest/'monitor.json').write_text('keep secret bytes',encoding='utf-8')
            (dest/'app.log').write_text('keep log bytes',encoding='utf-8')
            receipt=module.apply_plan(module.make_plan(source,dest),base/'backups',check_running=False)
            self.assertEqual(receipt['status'],'applied')
            self.assertTrue(all((dest/n).read_bytes()==b'new source' for n in module.CORE_FILES))
            self.assertTrue(all((Path(receipt['backup'])/'original'/n).read_bytes()==b'old source' for n in module.CORE_FILES))
            self.assertEqual((dest/'monitor.json').read_text(),'keep secret bytes')
            self.assertEqual((dest/'app.log').read_text(),'keep log bytes')
            self.assertEqual(module.apply_plan(module.make_plan(source,dest),base/'backups',check_running=False)['status'],'unchanged')

    def test_missing_core_never_partial_publish(self):
        module=self.load_sync()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            base=Path(directory);source,dest=self.fixture(base,module)
            (source/module.CORE_FILES[-1]).unlink()
            with self.assertRaises(FileNotFoundError):module.make_plan(source,dest)
            self.assertTrue(all((dest/n).read_bytes()==b'old source' for n in module.CORE_FILES))

    def test_running_monitor_blocks_before_backup(self):
        from unittest.mock import patch
        module=self.load_sync()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            base=Path(directory);source,dest=self.fixture(base,module)
            with patch.object(module,'running_monitors',return_value=[{'CommandLine':'pythonw.exe "'+str(dest/'openviking-monitor.pyw')+'"'}]):
                with self.assertRaisesRegex(RuntimeError,'still running'):
                    module.apply_plan(module.make_plan(source,dest),base/'backups')
            self.assertFalse((base/'backups').exists())


if __name__ == '__main__':
    unittest.main()
