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

with tempfile.TemporaryDirectory(prefix='ov-tmpdir-check-', dir=scratch) as folder:
    base = Path(folder)
    local_app = base / 'local'
    local_scratch = local_app / 'hermes/cache/scratch'
    payload = base / 'tmpdir_payload.py'
    payload.write_text('''import os, tempfile
from pathlib import Path
tmpdir = Path(os.environ['TMPDIR']).resolve()
assert tmpdir.is_relative_to(Path(os.environ['ISOLATION_SCRATCH']).resolve()), 'TMPDIR escaped scratch'
with tempfile.TemporaryDirectory(prefix='ov-sub-', dir=os.environ['TMPDIR']) as sub:
    probe = Path(sub) / 'probe.txt'
    probe.write_text('ok', encoding='utf-8')
    assert probe.read_text(encoding='utf-8') == 'ok'
print('TMPDIR_DEFAULT_OK')
''', encoding='utf-8')
    env = {k: v for k, v in os.environ.items() if k.upper() not in ('TMPDIR', 'TMP', 'TEMP', 'PYTHONPATH')}
    env.update(USERPROFILE=str(base / 'caller-home'), LOCALAPPDATA=str(local_app),
               ISOLATION_SCRATCH=str(local_scratch), PYTHONPATH='',
               PYTHONIOENCODING='utf-8', PYTHONDONTWRITEBYTECODE='1')
    result = subprocess.run([sys.executable, str(BOOTSTRAP), str(payload)], env=env,
                            capture_output=True, text=True, encoding='utf-8', timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'TMPDIR_DEFAULT_OK' in result.stdout, result.stdout

    (local_app / 'Temp').mkdir(parents=True, exist_ok=True)
    temp_env = dict(env, TMPDIR=str(local_app / 'Temp'))
    temp_res = subprocess.run([sys.executable, str(BOOTSTRAP), str(payload)], env=temp_env,
                              capture_output=True, text=True, encoding='utf-8', timeout=30)
    assert temp_res.returncode == 0, temp_res.stdout + temp_res.stderr
    assert 'TMPDIR_DEFAULT_OK' in temp_res.stdout, temp_res.stdout

    custom_dir = base / 'custom-tmp'
    custom_dir.mkdir()
    preserve_payload = base / 'tmpdir_preserve_payload.py'
    preserve_payload.write_text('''import os
from pathlib import Path
assert os.path.normcase(str(Path(os.environ['TMPDIR']).resolve())) == os.path.normcase(str(Path(os.environ['EXPECTED_TMPDIR']).resolve())), 'custom TMPDIR was clobbered'
print('TMPDIR_PRESERVED_OK')
''', encoding='utf-8')
    preserve_env = dict(env, TMPDIR=str(custom_dir), EXPECTED_TMPDIR=str(custom_dir))
    preserve_res = subprocess.run([sys.executable, str(BOOTSTRAP), str(preserve_payload)], env=preserve_env,
                                  capture_output=True, text=True, encoding='utf-8', timeout=30)
    assert preserve_res.returncode == 0, preserve_res.stdout + preserve_res.stderr
    assert 'TMPDIR_PRESERVED_OK' in preserve_res.stdout, preserve_res.stdout
print('SUITE_ISOLATION_OK')
