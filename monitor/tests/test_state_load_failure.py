"""Unreadable existing state must never become writable empty defaults."""
import os
from pathlib import Path
import runpy
import sys
import tempfile
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
namespace = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='state_load_failure_test')
glob = namespace['load_state'].__globals__

with tempfile.TemporaryDirectory(prefix='ov-state-load-', dir=os.environ['TMPDIR']) as folder:
    target = Path(folder) / 'monitor.json'
    glob.update(APP_DIR=Path(folder), STATE_PATH=target, APP_LOG=Path(folder) / 'app.log')
    original = b'{"spare_models":[{"api_key":"synthetic-only"}],"watch_keys":['
    target.write_bytes(original)
    loaded = namespace['load_state']()
    assert loaded.get('_state_load_error'), 'unreadable state was silently replaced by writable defaults'
    assert not loaded['watch_auto_enabled'] and not loaded['auto_probe_enabled']
    assert target.read_bytes() == original
    writer = Mock(side_effect=AssertionError('writer reached'))
    with patch.dict(glob, safe_atomic_write_json=writer):
        try:
            namespace['save_state'](loaded)
        except RuntimeError:
            pass
        else:
            raise AssertionError('save accepted unreadable state')
    writer.assert_not_called()
    assert target.read_bytes() == original, 'save overwrote damaged state'
    for original in (b'null', b'[]', b'123', b'"root"', b'', b'{"field":"\xff"}'):
        target.write_bytes(original)
        loaded = namespace['load_state']()
        assert loaded.get('_state_load_error'), 'invalid document did not lock state'
        try:
            namespace['save_state'](loaded)
        except RuntimeError:
            pass
        else:
            raise AssertionError('invalid document was writable')
        assert target.read_bytes() == original
    valid = b'{"watch_keys":[],"spare_models":[],"watch_auto_enabled":true,"auto_probe_enabled":true}'
    target.write_bytes(valid)
    for failure in (PermissionError, OSError, FileNotFoundError):
        with patch.object(Path, 'read_text', side_effect=failure('synthetic-sensitive-detail')):
            loaded = namespace['load_state']()
        assert loaded.get('_state_load_error'), 'existing unreadable file did not lock state'
        assert not loaded['watch_auto_enabled'] and not loaded['auto_probe_enabled']
        try:
            namespace['save_state'](loaded)
        except RuntimeError:
            pass
        else:
            raise AssertionError('read failure allowed state overwrite')
        assert target.read_bytes() == valid
    with patch.object(Path, 'exists', return_value=False), patch.object(Path, 'read_text', side_effect=PermissionError('synthetic-sensitive-detail')):
        loaded = namespace['load_state']()
    assert loaded.get('_state_load_error'), 'exists() hid an unreadable existing file'
    with patch.object(Path, 'read_text', side_effect=FileNotFoundError('synthetic-sensitive-detail')), \
         patch.object(Path, 'lstat', side_effect=PermissionError('synthetic-sensitive-detail')), \
         patch('os.path.lexists', return_value=False):
        loaded = namespace['load_state']()
    assert loaded.get('_state_load_error'), 'unverifiable absence was treated as a missing file'
    assert 'synthetic-sensitive-detail' not in glob['APP_LOG'].read_text(encoding='utf-8')
    target.write_bytes(valid)
    try:
        namespace['save_state'](loaded)
    except RuntimeError:
        pass
    else:
        raise AssertionError('restoring a file silently unlocked the current runtime')
    assert target.read_bytes() == valid
    restored = namespace['load_state']()
    assert not restored.get('_state_load_error'), 'explicit restore and reopen did not unlock healthy state'
    namespace['save_state'](restored)
    target.unlink()
    loaded = namespace['load_state']()
    assert not loaded.get('_state_load_error'), 'genuinely missing state must allow first-run save'
    namespace['save_state'](loaded)
    assert target.is_file()
print('STATE_LOAD_FAILURE_OK')
