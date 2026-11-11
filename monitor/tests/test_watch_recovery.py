"""Seven-record recovery, DPAPI and failure preservation on synthetic files only."""
import copy
import json
import os
from pathlib import Path
import queue
import runpy
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from watch_keys import WatchBatch, apply_watch_result, upsert_watch
import safe_write

ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='watch_recovery_test')
glob = ns['load_state'].__globals__
records = []
for i in range(7):
    records = upsert_watch(records, dict(alias=f'Key {i}', model=f'fixture/model-{i}',
                                       api_base='https://fixture.invalid/v1', api_key=f'synthetic-recovery-{i}'))
    records[-1] = apply_watch_result(records[-1], dict(ok=i % 2 == 0, ms=12, http_code=429 if i % 2 else 200), now=1000 + i)
state = dict(watch_keys=records, spare_models=[], watch_auto_enabled=False, watch_auto_migrated=True)
with tempfile.TemporaryDirectory(prefix='ov-watch-recovery-', dir=os.environ['TMPDIR']) as folder:
    target = Path(folder) / 'monitor.json'
    glob.update(APP_DIR=Path(folder), STATE_PATH=target, APP_LOG=Path(folder) / 'app.log')
    ns['save_state'](state)
    original = copy.deepcopy(state)
    backup = target.read_bytes()
    protected = json.loads(backup)
    assert all(r['api_key'].startswith('dpapi:') for r in protected['watch_keys'])
    assert b'synthetic-recovery-' not in backup
    loaded = ns['load_state']()
    assert len(loaded['watch_keys']) == 7
    for expected, actual in zip(records, loaded['watch_keys']):
        for name, value in expected.items():
            assert actual[name] == value, 'roundtrip changed record field: ' + name
    candidate = copy.deepcopy(loaded)
    candidate['watch_keys'][0]['alias'] = 'must not land'
    with patch.object(safe_write.os, 'replace', side_effect=PermissionError('synthetic disk failure')):
        try:
            ns['save_state'](candidate)
        except RuntimeError:
            pass
        else:
            raise AssertionError('failed replace was reported successful')
    assert target.read_bytes() == backup, 'failed replace lost original bytes'
    assert not list(Path(folder).glob('*.tmp')), 'failed save left temporary files'
    assert state == original
    target.write_text(json.dumps(dict(protected, watch_keys=[None])), encoding='utf-8')
    damaged = target.read_bytes()
    locked = ns['load_state']()
    assert locked.get('_watch_state_error') and not locked['watch_auto_enabled']
    try:
        ns['save_state'](locked)
    except RuntimeError:
        pass
    else:
        raise AssertionError('damaged state overwritten')
    assert target.read_bytes() == damaged
    target.write_bytes(backup)
    recovered = ns['load_state']()
    assert not recovered.get('_watch_state_error') and len(recovered['watch_keys']) == 7
    assert [r['api_key'] for r in recovered['watch_keys']] == [r['api_key'] for r in records]
    ns['save_state'](recovered)
    assert [r['api_key'] for r in json.loads(target.read_bytes())['watch_keys']] == [r['api_key'] for r in protected['watch_keys']]

for outcome in ('network', 'timeout', 'rate-limit', 'locked'):
    batch, events, calls = WatchBatch(), queue.Queue(), []
    item = copy.deepcopy(records[0])
    if outcome == 'locked':
        item.update(_dpapi_locked=True, api_key='')
    batch.sync([item])
    def probe(*args, **kwargs):
        calls.append(1)
        if outcome == 'network':
            raise OSError('synthetic failure containing nonpersistent data')
        return dict(ok=False, category=outcome, http_code=429 if outcome == 'rate-limit' else None)
    started = batch.start([item], probe, events.put)
    if outcome == 'locked':
        assert not started and not calls
        continue
    assert started
    batch.thread.join(5)
    assert not batch.thread.is_alive() and len(calls) == 1
    result = next(e[-1] for e in list(events.queue) if e[0] == 'watch_result')
    checked = apply_watch_result(item, result, now=2000, interval=60)
    assert checked['last_probe']['category'] == outcome
    assert checked['next_probe_at'] >= 2060 and checked['cooldown_until'] >= 2060
    assert 'nonpersistent' not in json.dumps(checked)
print('WATCH_RECOVERY_OK seven DPAPI records, failed save, restore, network/timeout/429/locked')
