"""Watch credentials are independent, bounded and revision-addressed."""
import copy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from watch_keys import MAX_WATCHES, upsert_watch, apply_watch_result, watch_due
except ImportError as exc:
    raise AssertionError('Watch credential store is not implemented') from exc


def fixture(index=0, **extra):
    return dict(alias=f'Key {index}', model='fixture/model', api_base='https://fixture.invalid/v1',
                api_key=f'synthetic-watch-{index}', **extra)


def rejected(fn, text):
    try:
        fn()
    except ValueError as exc:
        assert text in str(exc), str(exc)
    else:
        raise AssertionError('Expected ValueError: ' + text)


items = []
for index in range(MAX_WATCHES):
    items = upsert_watch(items, fixture(index))
assert MAX_WATCHES == 7 and len({item['id'] for item in items}) == 7
assert all(not item['auto_enabled'] for item in items)
assert len({(item['model'], item['api_base']) for item in items}) == 1
before = copy.deepcopy(items)
rejected(lambda: upsert_watch(items, fixture(8)), 'Tối đa 7')
assert items == before
old = items[0]
items = upsert_watch(items, dict(old, alias='Renamed'))
assert len(items) == 7 and items[0]['id'] == old['id'] and items[0]['rev'] > old['rev']
assert before[0]['alias'] == 'Key 0'
rejected(lambda: upsert_watch([], dict(fixture(), api_key='')), 'API key')
rejected(lambda: upsert_watch([], dict(fixture(), api_base='http://untrusted.invalid/v1')), 'HTTPS')
rejected(lambda: upsert_watch([], dict(fixture(), api_base='https://fixture.invalid/v1?key=secret')), 'URL')
rejected(lambda: upsert_watch([], dict(fixture(), id='unknown-id')), 'không còn')

locked = dict(items[0], api_key='', _enc='dpapi:synthetic-locked', _sha=None, _dpapi_locked=True)
updated = upsert_watch([locked], dict(locked, alias='Locked renamed'))[0]
assert updated['_enc'] == locked['_enc'] and updated['_dpapi_locked']
assert not watch_due(updated, 1000)

record = upsert_watch([], fixture())[0]
record = upsert_watch([record], dict(record, auto_enabled=True))[0]
assert watch_due(record, 1000)
state = apply_watch_result(record, {'ok':False,'category':'network','http_code':None,'ms':20,'at':1000}, now=1000, interval=60)
assert state['cooldown_until'] == 1060 and state['fail_streak'] == 1
state = apply_watch_result(state, {'ok':False,'category':'rate-limit','http_code':429,'ms':20,'at':1060}, now=1060, interval=60)
assert state['cooldown_until'] == 1180 and state['fail_streak'] == 2
assert not watch_due(state, 1100) and watch_due(state, 1180)
state = apply_watch_result(state, {'ok':True,'ms':20,'at':1180}, now=1180, interval=60)
assert state['fail_streak'] == 0 and state['cooldown_until'] == 0
assert state['next_probe_at'] == 1240
state = apply_watch_result(state, {'ok':False,'http_code':401,'category':'auth-or-quota','at':1240}, now=1240, interval=60)
assert state['auto_enabled']
state = apply_watch_result(state, {'ok':False,'http_code':403,'category':'auth-or-quota','at':1300}, now=1300, interval=60)
assert not state['auto_enabled'] and '401/403' in state['auto_disabled_reason']
state = upsert_watch([state], dict(state, api_key='new-synthetic-watch'))[0]
assert not state.get('last_probe') and state['fail_streak'] == 0 and not state['auto_disabled_reason']
assert state['api_key'] != record['api_key']
assert record.get('last_probe') is None
rejected(lambda: upsert_watch([], dict(fixture(), alias='bad\nline')), 'điều khiển')
rejected(lambda: upsert_watch([], dict(fixture(), model='bad\x00model')), 'điều khiển')
rejected(lambda: upsert_watch([], dict(fixture(), api_key='bad\x1fkey')), 'điều khiển')
for envelope in ('dpapi:synthetic-envelope', ' dpapi:synthetic-envelope '):
    rejected(lambda: upsert_watch([], dict(fixture(), api_key=envelope)), 'dpapi:')
    rejected(lambda: upsert_watch(items, {'id': items[0]['id'], 'api_key': envelope}), 'dpapi:')
assert upsert_watch([], dict(fixture(), api_key='${WATCH_TEST_KEY}'))[0]['api_key'] == '${WATCH_TEST_KEY}'
manual = upsert_watch([], fixture())[0]
for code in (401, 403):
    manual = apply_watch_result(manual, {'ok': False, 'http_code': code, 'category': 'auth-or-quota'}, now=2000)
assert manual['auth_fail_streak'] == 2 and not manual['auto_enabled']
assert not manual.get('auto_disabled_reason'), 'manual failures falsely claim Auto was disabled'
print('WATCH_KEYS_OK')
