"""Reopening Settings preserves the current form instead of creating stale copies."""
from pathlib import Path
import os
import runpy
import sys
import tkinter as tk

original_init = tk.Tk.__init__
def scaled_init(root, *args, **kwargs):
    original_init(root, *args, **kwargs)
    root.tk.call('tk', 'scaling', float(os.environ.get('MONITOR_TEST_SCALE', '1.333333')))
tk.Tk.__init__ = scaled_init

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
namespace = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='settings_singleton_test')
glob = namespace['run_gui'].__globals__
state = glob['load_state']()
state.update(run_with_windows=False, notify_on_down=False, notify_on_failover=False, always_on_top=False)
glob['load_state'] = lambda: state
errors = []


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def button(parent, text):
    return next(w for w in walk(parent) if w.winfo_class() == 'Button' and w.cget('text') == text)


def windows(root):
    return [w for w in root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == 'Cài đặt']


def loop(root, *args):
    root.report_callback_exception = lambda *exc: errors.append(exc[0].__name__)
    try:
        root.update()
        opener = button(root, 'Cài đặt')
        opener.invoke()
        root.update()
        first = windows(root)[0]
        notify = next(w for w in walk(first) if w.winfo_class() == 'Checkbutton' and
                      w.cget('text') == 'Thông báo khi OpenViking / watchdog gặp sự cố')
        notify.select()
        opener.invoke()
        root.update()
        assert windows(root) == [first], 'reopening Settings created a stale second form'
        assert root.getvar(notify.cget('variable')), 'reopening Settings discarded unsaved input'
        button(first, 'Lưu').invoke()
        root.update()
        assert state['notify_on_down'] is True
        assert not windows(root)
        opener.invoke()
        root.update()
        second = windows(root)[0]
        assert second is not first, 'closed Settings instance reused'
        notify = next(w for w in walk(second) if w.winfo_class() == 'Checkbutton' and
                      w.cget('text') == 'Thông báo khi OpenViking / watchdog gặp sự cố')
        assert root.getvar(notify.cget('variable')), 'new Settings form missed the latest save'
        button(second, 'Hủy').invoke()
        opener.invoke()
        root.update()
        assert len(windows(root)) == 1, 'cancel prevented reopening Settings'
        assert not errors, errors
        print('SETTINGS_SINGLETON_OK')
    finally:
        root.update_idletasks()
        root.destroy()


original_loop = tk.Tk.mainloop
tk.Tk.mainloop = loop
try:
    namespace['run_gui'](start_hidden=False)
finally:
    tk.Tk.mainloop = original_loop
    tk.Tk.__init__ = original_init
