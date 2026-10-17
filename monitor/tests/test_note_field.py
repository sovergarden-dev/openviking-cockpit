"""Ghi chú của dự trữ: phải có chỗ nhập và phải lưu được."""
import runpy
import sys
import tkinter as tk
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SRC = ROOT / 'openviking-monitor.pyw'
src = SRC.read_text(encoding='utf-8')
ns = runpy.run_path(str(SRC), run_name='note_test')

# 1. Trình sửa dự trữ (double-click một dòng) phải có ô Ghi chú và truyền nó khi lưu
assert 'vars_["note"]' in src, 'thiếu biến note trong trình sửa'
ed = src.split('def slot_editor')[1].split('def do_add')[0]
assert 'text="Ghi chú"' in ed and 'vars_["note"]' in ed, 'không có ô nhập Ghi chú trong trình sửa dự trữ'
assert 'if mode == "spare":' in ed, 'ô Ghi chú phải chỉ dành cho dự trữ'
assert 'save_form_as_spare(model, base, key, vars_["note"].get().strip())' in ed, \
    'do_save chưa truyền ghi chú vào bản ghi dự trữ'

# 2. Đường lưu phải giữ nguyên ghi chú (hàm thuần, không ghi file)
up = ns['upsert_spare']
items = up([], {'model': 'm1', 'api_base': 'http://x/v1', 'api_key': 'k1', 'note': 'ghi chú thử'})
assert items and items[0].get('note') == 'ghi chú thử', items
items = up(items, {'model': 'm1', 'api_base': 'http://x/v1', 'api_key': 'k1', 'note': 'sửa lại'})
assert len(items) == 1 and items[0]['note'] == 'sửa lại', items           # upsert: không nhân bản
items = up(items, {'model': 'm1', 'api_base': 'http://x/v1', 'api_key': 'k1', 'note': ''})
assert items[0].get('note') == '', 'xoá ghi chú phải ghi được chuỗi rỗng'

# 3. Cột Ghi chú: tick là hiện, bỏ tick là ẩn (đúng như UI hứa)
r = tk.Tk()
r.withdraw()
from reserve_table import ReserveTable
t = ReserveTable(r, preferences={})
t.pack()
t.render([dict(model='a', api_base='http://x/v1', note='có ghi chú')])
t.optional.set(True)
t.toggle_columns()
assert 'note' in t.tree.cget('displaycolumns')
vals = list(t.tree.item(t.tree.get_children()[0], 'values'))
assert vals[-1] == 'có ghi chú', f'cột Ghi chú không hiện nội dung: {vals!r}'
t.optional.set(False)
t.toggle_columns()
assert 'note' not in t.tree.cget('displaycolumns')
r.destroy()

# 4. End-to-end: mở trình sửa dự trữ thật (double-click) và gõ được vào ô Ghi chú
import json
import os
MON = Path(os.environ.get('USERPROFILE', r'C:\Users\rurus')) / '.openviking' / 'monitor'
state_path = MON / 'monitor.json'
before = json.loads(state_path.read_text(encoding='utf-8')).get('spare_models') if state_path.exists() else None
os.environ['MONITOR_NO_AUTOFIT'] = '1'
ns_gui = runpy.run_path(str(SRC), run_name='note_gui_test')
import tkinter as tk2
orig = tk2.Tk.mainloop
result = {'value': 'không chạy'}


def loop(groot, *args):
    def walk(w):
        yield w
        for c in w.winfo_children():
            yield from walk(c)

    def txt(w):
        try:
            t = w.cget('text')
            return t if isinstance(t, str) else ''
        except Exception:
            return ''

    def go():
        try:
            groot.update_idletasks()
            rt = next((w for w in walk(groot) if 'reservetable' in w.winfo_name()), None)
            assert rt is not None, 'không thấy bảng DỰ TRỮ'
            tree = next(w for w in walk(rt) if w.winfo_class() == 'Treeview')
            rows = tree.get_children()
            assert rows, 'bảng DỰ TRỮ chưa có dòng nào'
            tree.selection_set(rows[0])
            groot.update_idletasks()
            # Hai click đơn liên tiếp = một double-click thật (Tk tự đếm click)
            for _ in range(2):
                tree.event_generate('<Button-1>', x=140, y=25)
                groot.update()
            tops = [w for w in walk(groot) if w.winfo_class() == 'Toplevel']
            assert tops, 'double-click không mở được trình sửa dự trữ'
            ed = tops[-1]
            assert any(txt(w).strip() == 'Ghi chú' for w in walk(ed)), 'trình sửa thiếu nhãn Ghi chú'
            entry = next((w for w in walk(ed) if w.winfo_name() == 'note_entry'), None)
            assert entry is not None, 'trình sửa thiếu ô nhập Ghi chú'
            entry.insert(0, 'ghi chú kiểm thử')
            assert entry.get() == 'ghi chú kiểm thử', 'ô Ghi chú không nhận chữ'
            huys = [w for w in walk(ed) if txt(w).strip() == 'Hủy']
            assert huys, 'trình sửa thiếu nút Hủy'
            huys[0].invoke()
            groot.update()
            assert not [w for w in walk(groot) if w.winfo_class() == 'Toplevel'], 'Hủy mà cửa sổ vẫn mở'
            result['value'] = 'SPARE_NOTE_EDITOR_OK'
        except Exception as exc:
            result['value'] = f'FAIL {type(exc).__name__}: {exc}'
        finally:
            groot.quit()

    groot.after(3000, go)
    orig(groot, *args)


tk2.Tk.mainloop = loop
ns_gui['run_gui'](start_hidden=False)
assert result['value'] == 'SPARE_NOTE_EDITOR_OK', result['value']
after = json.loads(state_path.read_text(encoding='utf-8')).get('spare_models') if state_path.exists() else None
assert after == before, 'bấm Hủy mà dữ liệu dự trữ bị đổi'
print('NOTE_FIELD_OK')
