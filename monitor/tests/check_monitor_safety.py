"""Offline regression: execute production callbacks with isolated UI doubles."""
import ast
from pathlib import Path
import tkinter as tk

SOURCE = Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
tree = ast.parse(SOURCE.read_text(encoding='utf-8'))

def callback(name, env):
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), env)
    return env[name]

class UI:
    def __init__(self):
        self.value = ''
        self.jobs = []
    def clipboard_clear(self): self.value = ''
    def clipboard_append(self, value): self.value = value
    def clipboard_get(self): return self.value
    def after(self, delay, fn): self.jobs.append((delay, fn))
    def set(self, value): self.status = value

root = UI()
copy = callback('copy_secret', {'root': root, 'foot_var': root, 'tk': tk})
copy('synthetic-test-secret', 'Copied')
assert root.value == 'synthetic-test-secret'
assert root.jobs and root.jobs[-1][0] == 45000, 'Missing clipboard expiry'
root.jobs[-1][1]()
assert root.value == '', 'Secret did not expire'
copy('synthetic-test-secret', 'Copied')
root.value = 'new user clipboard'
root.jobs[-1][1]()
assert root.value == 'new user clipboard', 'Erased newer clipboard'
print('CLIPBOARD_EXPIRY_OK')

state = {'spare_models': [{'model': 'old'}]}
def fail_save(candidate):
    raise RuntimeError('simulated write failure')
env = {'state': state, 'save_state': fail_save, 'refresh_spares': lambda x: None, 'foot_var': root}
persist = callback('persist_spares', env)
try:
    persist([{'model': 'new'}])
except RuntimeError:
    pass
assert state['spare_models'] == [{'model': 'old'}], 'Failed write changed in-memory state'
print('SPARE_WRITE_ROLLBACK_OK')

from urllib.parse import urlsplit, urlunsplit
import hashlib
assert any(isinstance(n, ast.FunctionDef) and n.name == 'model_cache_key' for n in tree.body), 'Missing credential-scoped cache key'
cache_key = callback('model_cache_key', {'urlsplit': urlsplit, 'urlunsplit': urlunsplit, 'hashlib': hashlib})
assert cache_key('https://EXAMPLE.com/v1/', 'a') == cache_key('https://example.com/v1', 'a')
assert cache_key('https://example.com/V1', 'a') != cache_key('https://example.com/v1', 'a')
assert cache_key('https://example.com/v1', 'a') != cache_key('https://example.com/v1', 'b')
assert 'synthetic-test-secret' not in cache_key('https://example.com/v1', 'synthetic-test-secret')
print('MODEL_CACHE_SCOPE_OK')
