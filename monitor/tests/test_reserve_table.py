import os
import tkinter as tk
from tkinter import ttk as _ttk
import tkinter.font as tkfont
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from reserve_table import ReserveTable
except ImportError:
    raise AssertionError('ReserveTable chưa được triển khai')


def run_dpi_probe(scale):
    root = tk.Tk()
    root.tk.call('tk', 'scaling', scale)
    root.withdraw()
    table = ReserveTable(root, preferences={})
    row = dict(
        model='fixture',
        api_base='https://discovery-api.intern-ai.org.cn/v1',
        last_probe={'ok': False, 'text': 'auth-or-quota · HTTP 401', 'ms': 12345, 'at': 0},
    )
    table.render([row])
    style = _ttk.Style(root)
    table_font = tkfont.Font(root, font=style.lookup('Treeview', 'font') or 'TkDefaultFont')
    for column, value in (('endpoint', row['api_base']), ('status', row['last_probe']['text'])):
        width = int(table.tree.column(column, 'width'))
        required = table_font.measure(value) + 14
        assert width >= required, f'{scale} DPI {column} clipping: {width} < {required}'
    root.destroy()
    print(f'RESERVE_TABLE_DPI_OK {scale}')


if len(sys.argv) == 3 and sys.argv[1] == '--dpi-probe':
    run_dpi_probe(float(sys.argv[2]))
    raise SystemExit(0)

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
t.reset_layout()
assert int(t.tree.column('note', 'width')) == 0, 'reset phải giữ cột ghi chú ẩn khi chưa chọn'
assert t.preferences.get('auto_width') is True, 'reset phải bật lại autofit'
assert all(int(t.tree.column(col, 'width')) <= t.caps[col] for col in t.columns), 'reset phải tôn trọng trần DPI'

# autofit: cột phải đủ rộng cho nội dung và không tự tắt sau các lần render
import tkinter.font as tkfont
from tkinter import ttk as _ttk
fnt = tkfont.Font(r, font=_ttk.Style(r).lookup('Treeview', 'font') or 'TkDefaultFont')
long_status = 'auth-or-quota · HTTP 401'
long_row = dict(model='provider/' + 'long-model-segment-' * 5, api_base='https://api.experientiallabs.ai/v1',
                last_probe={'ok': False, 'text': long_status, 'ms': 12345, 'at': 0})
t.render([long_row])
mw = int(t.tree.column('model', 'width'))
assert mw >= fnt.measure(long_row['model']) + 14, f'cột model quá hẹp: {mw} < {fnt.measure(long_row["model"]) + 14}'
sw = int(t.tree.column('status', 'width'))
assert sw >= fnt.measure(long_status) + 14, f'cột status quá hẹp: {sw}'
ew = int(t.tree.column('endpoint', 'width'))
assert ew >= fnt.measure('https://api.experientiallabs.ai/v1') + 14, f'cột endpoint quá hẹp: {ew}'
t.render([long_row])
t.render([long_row])
assert t.preferences.get('auto_width') is not False, 'autofit tự tắt sau nhiều lần render'
# Toggling the note column must not look like a manual column drag.
note_row = dict(long_row, note='brief')
t.optional.set(True)
t.toggle_columns()
t.render([note_row])
t.optional.set(False)
t.toggle_columns()
t.render([note_row])
t.optional.set(True)
t.toggle_columns()
t.render([note_row])
assert t.preferences.get('auto_width') is True, f'note visibility toggle disabled autofit: {t.preferences.get("auto_width_off")}'
assert 'auto_width_off' not in t.preferences
assert t.preferences['show_note'] is True
t.optional.set(False)
t.toggle_columns()
t.remember()
saved_note_width = t.preferences['widths']['note']
assert saved_note_width > 0, 'hidden note column must retain its last visible width'
reopened_note = ReserveTable(r, preferences=dict(t.preferences))
assert int(reopened_note.tree.column('note', 'width')) == 0
reopened_note.optional.set(True)
reopened_note.toggle_columns()
assert int(reopened_note.tree.column('note', 'width')) == saved_note_width
r.destroy()

dpi_env = dict(os.environ, PYTHONPATH='', USERPROFILE=os.environ.get('USERPROFILE', str(Path.home())))
python = Path(sys.executable)
for scale in ('1.333333', '1.666667', '2.0'):
    result = subprocess.run(
        [str(python), str(Path(__file__).resolve()), '--dpi-probe', scale],
        capture_output=True, text=True, env=dpi_env, timeout=45,
    )
    assert result.returncode == 0, f'{scale} DPI probe failed:\n{result.stdout}\n{result.stderr}'
    assert f'RESERVE_TABLE_DPI_OK {scale}' in result.stdout, result.stdout
print('RESERVE_TABLE_OK')
