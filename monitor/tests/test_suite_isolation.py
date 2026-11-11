"""Standalone bootstrap must isolate USERPROFILE before any suite code runs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

BOOTSTRAP = Path(__file__).with_name('suite_bootstrap.py')
scratch = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData/Local') / 'hermes/cache/scratch'
scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='ov-isolation-check-', dir=scratch) as folder:
    base = Path(folder)
    caller_home = base / 'caller-home'
    state_path = caller_home / '.openviking/monitor/monitor.json'
    state_path.parent.mkdir(parents=True)
    original = b'{"sentinel":"must-not-change"}\n'
    state_path.write_bytes(original)
    suite = base / 'payload.py'
    suite.write_text('''import json, os
from pathlib import Path
home = Path(os.environ['USERPROFILE']).resolve()
caller = Path(os.environ['ISOLATION_CALLER_HOME']).resolve()
assert home != caller, 'bootstrap used caller USERPROFILE'
assert home.is_relative_to(Path(os.environ['ISOLATION_SCRATCH']).resolve()), 'test home escaped scratch'
state = home / '.openviking/monitor/monitor.json'
assert state.is_file(), 'isolated Monitor fixture missing'
fixture = json.loads(state.read_text(encoding='utf-8'))
assert fixture.get('auto_probe_enabled') is False
assert fixture.get('spare_models'), 'spare fixture missing'
assert Path.home().resolve() == home, 'Path.home escaped isolated USERPROFILE'
protected = caller / '.openviking/monitor/monitor.json'
try:
    protected.write_text('{"unexpected-caller-write":true}', encoding='utf-8')
except PermissionError:
    pass
else:
    raise AssertionError('bootstrap did not block writes to caller Monitor state')
state.write_text('{"isolated-write":true}', encoding='utf-8')
print('ISOLATED_PAYLOAD_OK')
''', encoding='utf-8')
    env = dict(os.environ, USERPROFILE=str(caller_home), TMPDIR=str(base), TMP=str(base),
               TEMP=str(base), ISOLATION_CALLER_HOME=str(caller_home), ISOLATION_SCRATCH=str(base),
               PYTHONPATH='', PYTHONIOENCODING='utf-8', PYTHONDONTWRITEBYTECODE='1')
    result = subprocess.run([sys.executable, str(BOOTSTRAP), str(suite)], env=env,
                            capture_output=True, text=True, encoding='utf-8', timeout=30)
    assert state_path.read_bytes() == original, 'caller Monitor state changed'
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'ISOLATED_PAYLOAD_OK' in result.stdout, result.stdout
print('SUITE_ISOLATION_OK')
