"""Hidden reserve content cannot expand the overview through Notebook sizing."""
from pathlib import Path
import runpy
import sys
import tkinter as tk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='notebook_boundary_test')
glob = ns['run_gui'].__globals__
state = glob['load_state']()
state.update(geometry='880x800', manual_split=True, reserve_split=99999)
glob['load_state'] = lambda: state
original = tk.Tk.mainloop

def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)

def loop(root, *args):
    try:
        root.update()
        tabs = next(w for w in walk(root) if w.winfo_class() == 'TNotebook')
        assert not any(w.winfo_class() == 'Panedwindow' for w in walk(root))
        before = (root.winfo_width(), root.winfo_height(), root.minsize())
        reserve = root.nametowidget(tabs.tabs()[1])
        tk.Label(reserve, text='oversized reserve fixture', width=500, height=90).pack()
        for index in (1, 0, 1, 0):
            tabs.select(index)
            root.update()
            assert (root.winfo_width(), root.winfo_height(), root.minsize()) == before
        assert int(tabs.cget('width')) == 1 and int(tabs.cget('height')) == 1
        print('NOTEBOOK_SIZE_BOUNDARY_OK')
    finally:
        root.update_idletasks()
        root.destroy()

tk.Tk.mainloop = loop
try:
    ns['run_gui'](start_hidden=False)
finally:
    tk.Tk.mainloop = original
