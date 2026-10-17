import ast
from pathlib import Path

p = Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
src = p.read_text(encoding='utf-8')
tree = ast.parse(src)
probe = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'probe_model')
env = {
    'json': __import__('json'),
    'time': __import__('time'),
    'http_json': lambda *a, **k: (503, None),
    'log_app': lambda *a, **k: None,
}
exec(compile(ast.Module(body=[probe], type_ignores=[]), str(p), 'exec'), env)
first = env['probe_model']('m', 'http://127.0.0.1:20128/v1', 'k')
second = env['probe_model']('m', 'http://127.0.0.1:20128/v1', 'k')
assert first['category'] == 'upstream'
assert second['category'] == 'upstream'
assert 'Cooldown' not in second['text']
print('NO_PROBE_COOLDOWN_OK')
