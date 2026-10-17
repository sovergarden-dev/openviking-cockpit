"""Trần chỗ chứa DỰ TRỮ: đủ 69 model, chặn cái thứ 70 (MAX_SPARES)."""
from pathlib import Path
import ast
import time

p = Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
src = p.read_text(encoding='utf-8')
t = ast.parse(src)

env = {'time': time}
for n in t.body:
    if isinstance(n, ast.Assign) and any(isinstance(tg, ast.Name) and tg.id == 'MAX_SPARES' for tg in n.targets):
        env['MAX_SPARES'] = ast.literal_eval(n.value)
assert env.get('MAX_SPARES') == 69, f"MAX_SPARES phải là 69, thấy {env.get('MAX_SPARES')}"

wanted = {'spare_fingerprint', 'normalize_spare', 'upsert_spare'}
body = [n for n in t.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
assert len(body) == 3, f"thiếu hàm trong .pyw: có {[n.name for n in body]}"
exec(compile(ast.Module(body=body, type_ignores=[]), str(p), 'exec'), env)
upsert = env['upsert_spare']

items = []
for i in range(69):
    items = upsert(items, {'model': f'dummy-model-{i}', 'api_base': 'http://localhost:9999/v1', 'api_key': 'k'})
assert len(items) == 69, f"phải chứa đủ 69, thấy {len(items)}"

raised = False
try:
    upsert(items, {'model': 'one-too-many', 'api_base': 'http://localhost:9999/v1', 'api_key': 'k'})
except ValueError as e:
    raised = True
    assert '69' in str(e), f"thông báo lỗi phải nêu trần 69: {e}"
assert raised, 'cái thứ 70 phải bị chặn'

again = upsert(items, {'model': 'dummy-model-0', 'api_base': 'http://localhost:9999/v1', 'api_key': 'k2'})
assert len(again) == 69, 'upsert bản ghi trùng fingerprint phải THAY THẾ, không thêm'
assert again[0].get('api_key') == 'k2', 'bản ghi thay thế phải giữ dữ liệu mới'

print('SPARE_CAPACITY_OK (69)')
