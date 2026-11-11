"""Watch modals retain focus and show validation errors where the user typed."""
from pathlib import Path
import sys
import tkinter as tk

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from watch_panel import WatchPanel

root = tk.Tk()
root.geometry('1020x600')
state = dict(watch_keys=[], watch_auto_enabled=False)
logs = []
colors = dict(surface='#171d26', line='#303b49', accent='#eab84b', muted='#9aa7b8',
              ink='#edf2f7', btn='#263242', hover='#304056', ok='#79d8b0', bad='#ff9494', warn='#eab84b')
source = dict(model='fixture/model', api_base='https://fixture.invalid/v1', api_key='', _dpapi_locked=True)
panel = WatchPanel(root, state=state, save=lambda _: None, probe=lambda *a, **k: None,
                   emit=lambda _: None, status=logs.append, sources=lambda: [('Dự trữ', source)], colors=colors, font='Segoe UI')
panel.pack(fill='both', expand=True)


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def label_texts(win):
    return [str(w.cget('text')) + (str(root.getvar(w.cget('textvariable'))) if w.cget('textvariable') else '')
            for w in walk(win) if w.winfo_class() == 'Label']


try:
    panel.pick_source()
    root.update()
    picker = next(w for w in walk(root) if w.winfo_class() == 'Toplevel')
    assert root.grab_current() == picker, 'source picker is not modal'
    tree = next(w for w in walk(picker) if w.winfo_class() == 'Treeview')
    tree.selection_set('0')
    next(w for w in walk(picker) if w.winfo_class() == 'Button' and w.cget('text') == 'Sao chép và sửa').invoke()
    assert any('không có key đọc được' in text for text in label_texts(picker)), 'picker error hidden behind modal'
    picker.destroy()
    panel.edit(new=True, source=dict(source, api_key='synthetic', _dpapi_locked=False))
    root.update()
    editor = next(w for w in walk(root) if w.winfo_class() == 'Toplevel')
    model = next(w for w in walk(editor) if w.winfo_name() == 'watch_model')
    model.delete(0, 'end')
    next(w for w in walk(editor) if w.winfo_class() == 'Button' and w.cget('text') == 'Lưu').invoke()
    assert any('Thiếu model dùng để thử' in text for text in label_texts(editor)), 'editor lacks specific inline error'
    assert editor.winfo_exists() and not state['watch_keys']
    print('WATCH_DIALOGS_OK')
finally:
    panel.close()
    root.update_idletasks()
    root.destroy()
