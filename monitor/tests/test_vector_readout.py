import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='vec_test')
f = ns['vectors_from_body']

# 0.4.22+ structured status
assert f({'result': {'status': {'vector_count': 947, 'index': 'default', 'collection': 'context'}}}) == {
    'vectors': 947,
    'indexes': 1,
}, 'structured status not parsed'

# legacy ASCII-table fallback
assert f({'result': {'status': '| TOTAL | 1 | 803 |\n'}})['vectors'] == 803, 'table fallback broken'

# degraded payloads must stay "unknown", never a fake number
assert f({'result': {'status': 'no table here'}}) == {'vectors': None, 'indexes': None}
assert f({'result': {'status': {'index': 'default'}}}) == {'vectors': None, 'indexes': 1}
assert f(None) == {'vectors': None, 'indexes': None}
assert f({'result': 'x'}) == {'vectors': None, 'indexes': None}

src = (ROOT / 'openviking-monitor.pyw').read_text(encoding='utf-8')
assert 'format=json' in src, 'monitor must request the JSON observer format'
assert 'vectors_from_body(v_body)' in src, 'collect() must use vectors_from_body'
print('VECTOR_READOUT_OK')
