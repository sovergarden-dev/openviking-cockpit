"""Quarantine removes only an explicitly selected backup, preserving primary and embedding."""
import ast
import copy
from pathlib import Path

source = Path(__file__).resolve().parents[1] / 'openviking-monitor.pyw'
tree = ast.parse(source.read_text(encoding='utf-8'))
ns = {}
names = {'vlm_credentials_list', 'apply_credentials', 'quarantine_slot'}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0)] + nodes, type_ignores=[])), str(source), 'exec'), ns)
assert 'quarantine_slot' in ns, 'backup quarantine mutator is missing'
raw = {'vlm': {'model': 'primary', 'api_base': 'https://a.invalid/v1', 'api_key': 'fixture',
               'credentials': [{'id': 'a', 'model': 'primary'}, {'id': 'b', 'model': 'secondary'}, {'id': 'c', 'model': 'bad'}]},
       'embedding': {'dense': {'model': 'fixture'}}}
original = copy.deepcopy(raw)
result = ns['quarantine_slot'](copy.deepcopy(raw), 2)
assert result['embedding'] == original['embedding']
assert result['vlm']['credentials'] == original['vlm']['credentials'][:2]
assert result['vlm']['model'] == 'primary' and result['vlm']['api_key'] == 'fixture'
assert raw == original
for index in (0, -1, 3, True):
    try:
        ns['quarantine_slot'](copy.deepcopy(raw), index)
    except ValueError:
        pass
    else:
        raise AssertionError(f'Unsafe slot accepted: {index}')
print('SLOT_QUARANTINE_OK')
