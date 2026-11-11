"""Failed settings persistence cannot change RAM, disk or Windows integration."""
import copy
import os
from pathlib import Path
import runpy
import sys
import tkinter as tk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='settings_transaction_test')
glob = ns['run_gui'].__globals__
state = glob['load_state']()
state.update(run_with_windows=False, notify_on_down=False, notify_on_failover=False, always_on_top=False)
glob['load_state'] = lambda: state
path = Path(os.environ['USERPROFILE']) / '.openviking/monitor/monitor.json'
before_bytes = path.read_bytes()
original_save = glob['save_state']
calls, errors = [], []
glob['set_run_with_windows'] = lambda enabled: calls.append(enabled) or True


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def loop(root, *args):
    root.report_callback_exception = lambda *exc: errors.append(exc)
    try:
        root.update()
        next(w for w in walk(root) if w.winfo_class() == 'Button' and w.cget('text') == 'Cài đặt').invoke()
        root.update()
        settings = next(w for w in walk(root) if w.winfo_class() == 'Toplevel')
        for check in [w for w in walk(settings) if w.winfo_class() == 'Checkbutton']:
            check.select()
        before_state = copy.deepcopy(state)
        topmost = root.attributes('-topmost')
        def fail_save(candidate):
            raise RuntimeError('synthetic locked-state failure')
        glob['save_state'] = fail_save
        save = next(w for w in walk(settings) if w.winfo_class() == 'Button' and w.cget('text') == 'Lưu')
        save.invoke()
        root.update()
        assert state == before_state, 'failed settings save changed shared RAM'
        assert not calls, 'failed settings save changed startup integration'
        assert root.attributes('-topmost') == topmost
        assert path.read_bytes() == before_bytes
        assert settings.winfo_exists(), 'failed save silently closed the dialog'
        assert not errors, 'failed save leaked a Tk callback exception'
        visible = [str(w.cget('text')) for w in walk(settings) if w.winfo_class() == 'Label']
        variables = [root.getvar(w.cget('textvariable')) for w in walk(settings)
                     if w.winfo_class() == 'Label' and w.cget('textvariable')]
        assert any('Không lưu được' in str(value) for value in visible + variables), 'missing inline save error'
        glob['save_state'] = original_save
        save.invoke()
        root.update()
        assert all(state[k] for k in ('run_with_windows', 'notify_on_down', 'notify_on_failover', 'always_on_top'))
        assert calls == [True]
        assert path.read_bytes() != before_bytes
        assert not errors
        print('SETTINGS_TRANSACTION_OK')
    finally:
        glob['save_state'] = original_save
        root.update_idletasks()
        root.destroy()


original_loop = tk.Tk.mainloop
tk.Tk.mainloop = loop
try:
    ns['run_gui'](start_hidden=False)
finally:
    tk.Tk.mainloop = original_loop
