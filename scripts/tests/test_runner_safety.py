import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
PY=Path(os.environ.get('LOCALAPPDATA','C:/Users/rurus/AppData/Local'))/'Programs/Python/Python311/python.exe'

class RunnerGateTests(unittest.TestCase):
    def test_failing_pytest_body_cannot_exit_green(self):
        bootstrap=ROOT/'monitor/tests/suite_bootstrap.py'
        self.assertTrue(bootstrap.is_file(),'Isolated test bootstrap missing')
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path=Path(directory)/'test_fixture.py'
            path.write_text('import pytest\n\ndef test_must_execute():\n    assert False, "intentional red body"\n',encoding='utf-8')
            run=subprocess.run([str(PY),str(bootstrap),str(path)],capture_output=True,text=True,timeout=30)
            self.assertNotEqual(run.returncode,0)
            self.assertIn('intentional red body',run.stdout+run.stderr)

    def test_production_pid_guard_branch_removed(self):
        source=(ROOT/'monitor/tests/test_stale_lock_guard.py').read_text(encoding='utf-8')
        self.assertNotIn('run_guard(real_lock)',source)

if __name__=='__main__':
    unittest.main()
