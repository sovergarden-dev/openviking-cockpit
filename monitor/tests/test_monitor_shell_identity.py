"""Monitor shortcuts and process share one Windows taskbar identity."""
import ast
import ctypes
import json
import os
from pathlib import Path
import runpy
import struct
import sys
import tempfile
import tkinter as tk
from unittest.mock import patch


class StopBeforeTk(Exception):
    pass


def before_tk(*args, **kwargs):
    get_id = ctypes.windll.shell32.GetCurrentProcessExplicitAppUserModelID
    get_id.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    get_id.restype = ctypes.c_long
    result = ctypes.c_void_p()
    assert get_id(ctypes.byref(result)) == 0, 'process AppUserModelID was not set before Tk creation'
    try:
        assert ctypes.wstring_at(result) == glob['APP_USER_MODEL_ID'], 'process and shortcut identities differ'
    finally:
        ctypes.windll.ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        ctypes.windll.ole32.CoTaskMemFree(result)
    raise StopBeforeTk()

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
source = ROOT / 'openviking-monitor.pyw'
namespace = runpy.run_path(str(source), run_name='shell_identity_test')
glob = namespace['run_gui'].__globals__
tree = ast.parse(source.read_text(encoding='utf-8-sig'))
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_hidden')
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), glob)
path = Path(os.environ['USERPROFILE']) / '.openviking/monitor/identity-fixture.lnk'
assert 'ov-suite-' in str(path), 'Shell identity checks require suite_bootstrap isolation'
assert glob['make_shortcut'](path, '--tray', window_style=7), 'scratch shortcut creation failed'
quoted = str(path.parent).replace("'", "''")
name = path.name.replace("'", "''")
code, text = glob['run_hidden'](['powershell', '-NoProfile', '-Command',
    f"$folder=(New-Object -ComObject Shell.Application).Namespace('{quoted}'); "
    f"$item=$folder.ParseName('{name}'); "
    "@{appid=$item.ExtendedProperty('System.AppUserModel.ID')} | ConvertTo-Json -Compress"], timeout=15)
assert code == 0, 'scratch shortcut identity readback failed'
assert json.loads(text)['appid'] == glob['APP_USER_MODEL_ID'], 'shortcut has no matching AppUserModelID'
path.unlink()
try:
    glob['set_shortcut_app_id'](path)
except OSError:
    pass
else:
    raise AssertionError('identity writer accepted a missing shortcut')

with patch.dict(glob, run_hidden=lambda *args, **kwargs: (0, ''),
                set_shortcut_app_id=lambda target: (_ for _ in ()).throw(OSError('synthetic-only'))):
    path.write_bytes(b'synthetic-shortcut')
    assert glob['make_shortcut'](path, '') is False, 'identity persistence failure was reported as success'
path.unlink()

icon = ROOT / 'openviking.ico'
raw = icon.read_bytes()
reserved, kind, count = struct.unpack_from('<HHH', raw)
assert (reserved, kind) == (0, 1), 'invalid bundled icon'
sizes = {(raw[6 + 16 * i] or 256, raw[7 + 16 * i] or 256) for i in range(count)}
assert {(16, 16), (32, 32), (48, 48), (256, 256)} <= sizes, 'bundled taskbar icon lacks required resolutions'
with tempfile.TemporaryDirectory(dir=path.parent) as directory:
    fallback = Path(directory) / 'legacy-helper.exe'
    fallback.touch()
    with patch.dict(glob, HELPER_EXE=fallback):
        assert glob['shortcut_icon']() == str(glob['ICON_FILE']), 'shortcut still prefers legacy Helper artwork'
        assert glob['load_helper_icon'](32), 'window icon still loads the legacy Helper instead of bundled artwork'

with patch.object(tk, 'Tk', before_tk):
    try:
        glob['run_gui'](False)
    except StopBeforeTk:
        pass
print('MONITOR_SHELL_IDENTITY_OK')
