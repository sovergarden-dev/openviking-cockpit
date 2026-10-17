import ast
from pathlib import Path
p=Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
t=ast.parse(p.read_text(encoding='utf-8'))
env={}
def fn(name):
    node=next(n for n in ast.walk(t) if isinstance(n,ast.FunctionDef) and n.name==name)
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(p),'exec'),env)
    return env[name]
env['model_cache_key']=fn('model_cache_key')
origin=fn('key_origin')
assert origin('https://a/v1','secret','https://a/v1','secret')=='inherited'
assert origin('https://b/v1','secret','https://a/v1','secret')=='manual'
assert origin('https://a/v1','new','https://a/v1','secret')=='manual'
assert origin('https://a/v1','','https://a/v1','secret')=='empty'
print('ENDPOINT_KEY_SAFETY_OK')
