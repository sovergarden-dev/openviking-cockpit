import sys
import tkinter as tk
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from reserve_table import ReserveTable
except ImportError:
    raise AssertionError('ReserveTable chưa được triển khai')
r = tk.Tk()
r.withdraw()
t = ReserveTable(r)
items = [dict(model='zeta', api_base='http://localhost:9100/v1', last_probe=dict(ok=True, ms=12)), dict(model='alpha', api_base='http://localhost:8100/v1', last_probe=dict(ok=False, ms=100))]
t.render(items)
t.selection_set(0)
t.sort_by('model')
assert t.selected_indices() == [0], 'sorting changed record identity'
t.query.set('alpha')
r.update()
assert len(t.tree.get_children()) == 1
assert t.tree.item(t.tree.get_children()[0], 'values')[0] == 'alpha'
t.query.set('')
t.render(items)
t.selection_set(1)
t.render(items)
assert t.selected_indices() == [1], 'refresh lost selection'
t.render([])
assert t.selected_indices() == []
t.sort_by('ms')
prefs = dict(t.preferences)
reopened = ReserveTable(r, preferences=prefs)
assert reopened.sort_column == 'ms', 'sort order not restored'
reopened.optional.set(True)
reopened.toggle_columns()
reopened.reset_layout()
assert not reopened.optional.get(), 'reset left optional column enabled'

# Cột Ghi chú: ý người dùng quyết định — tick là luôn hiện (dù chưa có ghi chú nào)
assert 'note' not in t.tree.cget('displaycolumns'), 'mặc định không tick thì cột phải ẩn'
t.optional.set(True)
t.render([dict(model='n1', api_base='http://x/v1')])
assert 'note' in t.tree.cget('displaycolumns'), 'đã tick Ghi chú thì cột phải hiện dù rỗng'
t.render([dict(model='n1', api_base='http://x/v1', note='ghi chú')])
assert 'note' in t.tree.cget('displaycolumns'), 'cột Ghi chú có nội dung nhưng bị ẩn'
t.optional.set(False)
t.toggle_columns()
assert 'note' not in t.tree.cget('displaycolumns'), 'bỏ tick thì cột phải ẩn lại'

# autofit: cột phải đủ rộng cho nội dung và không tự tắt sau các lần render
import tkinter.font as tkfont
from tkinter import ttk as _ttk
fnt = tkfont.Font(r, font=_ttk.Style(r).lookup('Treeview', 'font') or 'TkDefaultFont')
long_status = 'auth-or-quota · HTTP 401'
long_row = dict(model='openrouter/stealth/space-bunny-alpha', api_base='https://api.experientiallabs.ai/v1',
                last_probe={'ok': False, 'text': long_status, 'ms': 12345, 'at': 0})
t.render([long_row])
sw = int(t.tree.column('status', 'width'))
assert sw >= fnt.measure(long_status) + 14, f'cột status quá hẹp: {sw}'
ew = int(t.tree.column('endpoint', 'width'))
assert ew >= fnt.measure('https://api.experientiallabs.ai/v1') + 14, f'cột endpoint quá hẹp: {ew}'
t.render([long_row])
t.render([long_row])
assert t.preferences.get('auto_width') is not False, 'autofit tự tắt sau nhiều lần render'
r.destroy()
print('RESERVE_TABLE_OK')
