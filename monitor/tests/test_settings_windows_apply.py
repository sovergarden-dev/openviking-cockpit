"""Saved preferences do not imply Windows startup integration succeeded."""
import json
import os
from pathlib import Path
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
namespace = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='settings_windows_apply_test')
glob = namespace['run_gui'].__globals__
state = glob['load_state']()
state.update(run_with_windows=False, notify_on_down=False, notify_on_failover=False, always_on_top=False)
glob['load_state'] = lambda: state
path = Path(os.environ['USERPROFILE']) / '.openviking/monitor/monitor.json'
assert 'ov-suite-' in str(path)
results = iter((False, True, False, True))
calls, errors = [], []


def apply_startup(enabled):
    calls.append(enabled)
    return next(results)


glob['set_run_with_windows'] = apply_startup


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def button(parent, text):
    return next(w for w in walk(parent) if w.winfo_class() == 'Button' and w.cget('text') == text)


def loop(root, *args):
    root.report_callback_exception = lambda *exc: errors.append(exc[0].__name__)
    try:
        root.update()
        for enabled in (True, False):
            button(root, 'Cài đặt').invoke()
            root.update()
            window = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            startup = next(w for w in walk(window) if w.winfo_class() == 'Checkbutton' and
                           str(w.cget('text')).startswith('Khởi động cùng Windows'))
            startup.select() if enabled else startup.deselect()
            button(window, 'Lưu').invoke()
            root.update()
            assert window.winfo_exists(), 'failed Windows apply silently closed Settings'
            assert state['run_with_windows'] is enabled
            assert json.loads(path.read_text(encoding='utf-8'))['run_with_windows'] is enabled
            messages = [str(root.getvar(w.cget('textvariable'))) for w in walk(window)
                        if w.winfo_class() == 'Label' and w.cget('textvariable')]
            assert any('Đã lưu' in text and 'chưa áp dụng' in text for text in messages), messages
            button(window, 'Lưu').invoke()
            root.update()
            assert not window.winfo_exists(), 'retry did not close successfully applied Settings'
        assert calls == [True, True, False, False], calls
        assert not errors, errors
        print('SETTINGS_WINDOWS_APPLY_OK')
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
