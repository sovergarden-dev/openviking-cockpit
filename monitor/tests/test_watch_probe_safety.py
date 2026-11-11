"""Bounded probes do not persist provider body, token or request URL."""
import ast
import json
from pathlib import Path
import runpy
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from secret_store import SecretStatus, resolve_secret
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='watch_probe_safety')
source = ROOT / 'openviking-monitor.pyw'
probe_node = next(node for node in ast.parse(source.read_text(encoding='utf-8')).body
                  if isinstance(node, ast.FunctionDef) and node.name == 'probe_model')
glob = dict(json=json, time=time, resolve_secret=resolve_secret, SecretStatus=SecretStatus)
exec(compile(ast.Module(body=[probe_node], type_ignores=[]), str(source), 'exec'), glob)
ns['probe_model'] = glob['probe_model']
assert 'max_tokens' in ns['probe_model'].__annotations__, 'probe_model needs an explicit optional token budget'
calls, logs = [], []
glob['log_app'] = logs.append

def http(url, **kwargs):
    calls.append((url, kwargs))
    return 401, {'error': 'Bearer synthetic-provider-secret ?key=synthetic-query-secret'}
glob['http_json'] = http
result = ns['probe_model']('fixture/model', 'https://fixture.invalid/v1', 'synthetic-credential', timeout=20, max_tokens=64)
assert result['http_code'] == 401
assert 'synthetic-provider-secret' not in str(result) + str(logs)
assert 'synthetic-query-secret' not in str(result) + str(logs)
assert calls[0][1]['timeout'] == 20
assert json.loads(calls[0][1]['body'])['max_tokens'] == 64
assert ns['http_fail_text'](RuntimeError('https://fixture.invalid?key=synthetic-query-secret')) == 'RuntimeError'
redact = ns['redact']
for text in ('Bearer synthetic-bearer-secret', '?key=synthetic-query-secret',
             'sk-syntheticcredential123456789', 'AIzaSyntheticCredential123456789',
             'gsk_syntheticcredential123456789', 'xai-syntheticcredential123456789'):
    assert 'synthetic' not in redact(text).lower(), 'redactor missed a supported token form'
print('WATCH_PROBE_SAFETY_OK')
