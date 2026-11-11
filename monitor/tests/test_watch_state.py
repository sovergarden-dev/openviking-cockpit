"""Watch state: DPAPI roundtrip and migration without touching live files."""
import copy
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='watch_state_test')
glob = ns['load_state'].__globals__
scratch = Path(os.environ['LOCALAPPDATA']) / 'hermes/cache/scratch'
with tempfile.TemporaryDirectory(prefix='ov-watch-state-', dir=scratch) as folder:
    target = Path(folder)
    glob.update(APP_DIR=target, STATE_PATH=target / 'monitor.json', APP_LOG=target / 'app.log')
    original = {'spare_models': [{'model':'spare','api_key':'synthetic-spare'}], 'auto_probe_enabled':True}
    glob['STATE_PATH'].write_text(json.dumps(original), encoding='utf-8')
    loaded = ns['load_state']()
    assert loaded.get('watch_keys') == [], 'missing independent empty watch list'
    assert loaded.get('watch_auto_enabled') is False, 'old Auto must not start new watch jobs'
    assert loaded.get('auto_probe_enabled') is False, 'old slot Auto must be disabled'
    assert json.loads(glob['STATE_PATH'].read_text()) == original, 'load mutated disk'
    loaded['watch_keys'] = [{'id':'watch-fixture','model':'m','api_base':'https://fixture.invalid/v1',
                              'api_key':'synthetic-watch-credential','alias':'Test','rev':1,'auto_enabled':False}]
    loaded['watch_auto_enabled'] = True
    ns['save_state'](loaded)
    saved = json.loads(glob['STATE_PATH'].read_text())
    cipher = saved['watch_keys'][0]['api_key']
    assert cipher.startswith('dpapi:'), 'watch saved without DPAPI'
    assert 'synthetic-watch-credential' not in glob['STATE_PATH'].read_text()
    reloaded = ns['load_state']()
    assert reloaded['watch_keys'][0]['api_key'] == 'synthetic-watch-credential'
    assert reloaded['watch_auto_enabled'] is True
    reloaded['watch_keys'][0]['alias'] = 'Renamed'
    ns['save_state'](reloaded)
    assert json.loads(glob['STATE_PATH'].read_text())['watch_keys'][0]['api_key'] == cipher
    broken = 'dpapi:synthetic-invalid-envelope'
    saved['watch_keys'][0]['api_key'] = broken
    glob['STATE_PATH'].write_text(json.dumps(saved), encoding='utf-8')
    locked = ns['load_state']()
    assert locked['watch_keys'][0]['_dpapi_locked'] and locked['watch_keys'][0]['api_key'] == ''
    locked['watch_keys'][0]['alias'] = 'Still locked'
    ns['save_state'](locked)
    assert json.loads(glob['STATE_PATH'].read_text())['watch_keys'][0]['api_key'] == broken
    legacy = copy.deepcopy(saved)
    legacy['watch_keys'][0]['api_key'] = 'synthetic-legacy-watch'
    glob['STATE_PATH'].write_text(json.dumps(legacy), encoding='utf-8')
    ns['save_state'](ns['load_state']())
    assert json.loads(glob['STATE_PATH'].read_text())['watch_keys'][0]['api_key'].startswith('dpapi:'), 'legacy watch plaintext was preserved'
    before = glob['STATE_PATH'].read_bytes()
    too_many = copy.deepcopy(locked)
    too_many['watch_keys'] = [dict(locked['watch_keys'][0], id=f'watch-{i}') for i in range(8)]
    try:
        ns['save_state'](too_many)
    except RuntimeError:
        pass
    else:
        raise AssertionError('save_state accepted more than 7 watch keys')
    assert glob['STATE_PATH'].read_bytes() == before
    null_state = dict(original, watch_keys=None)
    glob['STATE_PATH'].write_text(json.dumps(null_state), encoding='utf-8')
    normalized = ns['load_state']()
    assert normalized['watch_keys'] == [], 'null watch list was not normalized'
    ns['save_state'](normalized)
    assert json.loads(glob['STATE_PATH'].read_text())['watch_keys'] == []
    valid = saved['watch_keys'][0]
    malformed = ('invalid', {}, [None], [{'model': 'missing-id'}], [valid, valid],
                 [dict(valid, api_key=123)], [dict(valid, next_probe_at='invalid')],
                 [dict(valid, last_probe={'at': 'invalid'})])
    for damaged in malformed:
        glob['STATE_PATH'].write_text(json.dumps(dict(original, watch_keys=damaged, watch_auto_enabled=True)), encoding='utf-8')
        before = glob['STATE_PATH'].read_bytes()
        protected = ns['load_state']()
        assert protected['watch_keys'] == [] and not protected['watch_auto_enabled']
        assert protected.get('_watch_state_error'), 'damaged watch data must disable state writes'
        assert glob['STATE_PATH'].read_bytes() == before, 'load changed damaged state'
        try:
            ns['save_state'](protected)
        except RuntimeError:
            pass
        else:
            raise AssertionError('damaged state was overwritten with an empty list')
        assert glob['STATE_PATH'].read_bytes() == before
print('WATCH_STATE_DPAPI_OK')
