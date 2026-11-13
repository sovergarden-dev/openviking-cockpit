"""Startup integration acknowledges shell status and verifies scratch files."""
import ast
import os
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
source = ROOT / 'openviking-monitor.pyw'
namespace = runpy.run_path(str(source), run_name='startup_shortcut_test')
glob = namespace['run_gui'].__globals__
node = next(n for n in ast.parse(source.read_text(encoding='utf-8-sig')).body
            if isinstance(n, ast.FunctionDef) and n.name == 'set_run_with_windows')
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), glob)
path = Path(os.environ['USERPROFILE']) / '.openviking/monitor/synthetic-startup.lnk'
assert 'ov-suite-' in str(path), 'Startup tests require suite_bootstrap isolation'
glob['startup_shortcut_path'] = lambda: path
logs = []
glob['log_app'] = logs.append
real_identity_writer = glob['set_shortcut_app_id']
glob['set_shortcut_app_id'] = lambda target: None


def create_shell_file(*args, **kwargs):
    path.write_bytes(b'synthetic-shortcut')
    return 0, ''


glob['run_hidden'] = lambda *args, **kwargs: (1, 'synthetic-sensitive-shell-output')
assert glob['set_run_with_windows'](True) is False, 'failed shell command was not acknowledged'
assert not path.exists()
glob['run_hidden'] = lambda *args, **kwargs: (0, '')
assert glob['set_run_with_windows'](True) is False, 'exit zero without a shortcut was accepted'
glob['run_hidden'] = create_shell_file
assert glob['set_run_with_windows'](True) is True, 'verified shortcut was not acknowledged'
assert path.is_file()
assert glob['set_run_with_windows'](False) is True
assert not path.exists()
assert glob['set_run_with_windows'](False) is True, 'already-disabled startup should succeed'
path.write_bytes(b'synthetic-shortcut')
with patch.object(Path, 'unlink', side_effect=PermissionError('synthetic-sensitive-unlink-output')):
    assert glob['set_run_with_windows'](False) is False, 'failed unlink was not acknowledged'
assert path.exists()
assert not any('synthetic-sensitive' in line for line in logs), 'raw error reached app log'
assert glob['set_run_with_windows'](False) is True
shell_node = next(n for n in ast.parse(source.read_text(encoding='utf-8-sig')).body
                  if isinstance(n, ast.FunctionDef) and n.name == 'run_hidden')
exec(compile(ast.Module(body=[shell_node], type_ignores=[]), str(source), 'exec'), glob)
glob['set_shortcut_app_id'] = real_identity_writer
assert glob['set_run_with_windows'](True) is True, 'real scratch shortcut creation failed'
assert path.is_file() and path.stat().st_size > 0
quoted = str(path).replace("'", "''")
code, text = glob['run_hidden'](['powershell', '-NoProfile', '-Command',
                               f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{quoted}'); "
                               "$s.Arguments"], timeout=15)
assert code == 0 and '--tray' in text, 'scratch startup shortcut has wrong arguments'
assert glob['set_run_with_windows'](False) is True
assert not path.exists()

# Verify is_live_installation helper handles both live and external locations
is_live = glob.get('is_live_installation')
assert callable(is_live), 'is_live_installation helper missing'
# In test environment, running script is in repo (ROOT), outside isolated APP_DIR
assert is_live() is False, 'running from repo must not be recognized as live install'
with patch.dict(glob, {'APP_DIR': ROOT}):
    assert glob['is_live_installation']() is True, 'matching APP_DIR must be recognized as live install'

# Verify make_shortcut handles paths with apostrophes and reads back valid arguments
apo_path = path.with_name("synthetic-o'connor-test.lnk")
assert 'ov-suite-' in str(apo_path), 'apostrophe test path must be in isolated sandbox'
try:
    assert glob['make_shortcut'](apo_path, "--tray", window_style=7) is True, 'apostrophe shortcut path failed'
    assert apo_path.is_file() and apo_path.stat().st_size > 0
    apo_quoted = str(apo_path).replace("'", "''")
    code, text = glob['run_hidden'](['powershell', '-NoProfile', '-Command',
                                   f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{apo_quoted}'); "
                                   "$s.Arguments"], timeout=15)
    assert code == 0 and '--tray' in text, 'apostrophe shortcut readback failed'
finally:
    apo_path.unlink(missing_ok=True)

print('STARTUP_SHORTCUT_OK')
