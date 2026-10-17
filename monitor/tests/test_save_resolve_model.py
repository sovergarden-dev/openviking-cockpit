from pathlib import Path
import ast
p=Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
src=p.read_text(encoding='utf-8')
t=ast.parse(src)
env={}
node=next(n for n in ast.walk(t) if isinstance(n,ast.FunctionDef) and n.name=='resolve_form_model')
exec(compile(ast.Module(body=[node],type_ignores=[]),str(p),'exec'),env)
fn=env['resolve_form_model']
assert fn('typed', ['other'])=='typed'
assert fn('', ['gemini-3.8-flash-high    2068 ms'])=='gemini-3.8-flash-high'
assert fn('', [])==''
print('SAVE_RESOLVE_MODEL_OK')
