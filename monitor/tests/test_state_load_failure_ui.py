"""Damaged state survives startup auto-fit, Settings, Watch edits and exit."""
import os
from pathlib import Path
import runpy
import sys
import tkinter as tk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
namespace = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='state_load_failure_ui_test')
glob = namespace['run_gui'].__globals__
target = glob['STATE_PATH']
original = b'{"watch_keys":[{"api_key":"synthetic-sensitive-detail"}'
target.write_bytes(original)
state = glob['load_state']()
assert state.get('_state_load_error'), 'fixture did not lock damaged state'
glob['load_state'] = lambda: state
side_effects, save_attempts, errors = [], [], []
actual_save = glob['save_state']

def traced_save(candidate):
    save_attempts.append(dict(candidate))
    return actual_save(candidate)

glob.update(save_state=traced_save, set_run_with_windows=lambda enabled: side_effects.append(enabled))
original_init, original_loop = tk.Tk.__init__, tk.Tk.mainloop

def scaled_init(root, *args, **kwargs):
    original_init(root, *args, **kwargs)
    root.tk.call('tk', 'scaling', float(os.environ.get('MONITOR_TEST_SCALE', '1.333333')))

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
        warning = next((w for w in walk(root) if w.winfo_name() == 'state_warning'), None)
        assert warning is not None and warning.winfo_ismapped(), 'missing persistent state recovery warning'
        assert warning.cget('text') == state['_state_load_error']
        assert warning.winfo_height() >= warning.winfo_reqheight(), 'recovery warning vertically clipped'
        assert not side_effects
        after_callbacks = [root.tk.splitlist(root.tk.call('after', 'info', item))[0]
                           for item in root.tk.splitlist(root.tk.call('after', 'info'))]
        assert any(command.endswith('auto_fit_once') for command in after_callbacks), 'startup auto-fit callback missing'
        final_fit = [command for command in after_callbacks if command.endswith('<lambda>')]
        assert len(final_fit) == 1, 'ambiguous final startup auto-fit callback'
        root.tk.call(final_fit[0])
        assert save_attempts and save_attempts[-1].get('geometry_autofit'), 'final startup auto-fit save not exercised'
        assert target.read_bytes() == original
        button(root, 'Cài đặt').invoke()
        root.update()
        settings = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == 'Cài đặt')
        checkbox = next(w for w in walk(settings) if w.winfo_class() == 'Checkbutton' and
                        w.cget('text') == 'Khởi động cùng Windows (chạy ngầm dưới khay hệ thống)')
        checkbox.select()
        button(settings, 'Lưu').invoke()
        root.update()
        assert settings.winfo_exists(), 'failed save closed Settings'
        assert not state['run_with_windows'] and not side_effects, 'failed save applied runtime/Windows changes'
        messages = [root.getvar(w.cget('textvariable')) for w in walk(settings)
                    if w.winfo_class() == 'Label' and w.cget('textvariable')]
        assert state['_state_load_error'] in messages, 'Settings omitted recovery instructions'
        button(settings, 'Thu cửa sổ vừa nội dung').invoke()
        root.update()
        assert warning.cget('text') == state['_state_load_error'] and warning.winfo_ismapped(), 'status update erased recovery warning'
        panel = next(w for w in walk(root) if w.winfo_name() == 'watch_panel')
        assert not panel.auto.get()
        panel.auto_check.invoke()
        assert not panel.auto.get() and not state['watch_auto_enabled'], 'failed Auto save enabled scheduler'
        assert not panel.store(dict(alias='Fixture', model='fixture', api_base='https://fixture.invalid/v1', api_key='synthetic-only'))
        assert not state['watch_keys'] and target.read_bytes() == original
        button(settings, 'Hủy').invoke()
        before_exit = len(save_attempts)
        root.tk.call(root.protocol('WM_DELETE_WINDOW'))
        assert len(save_attempts) == before_exit + 1, 'exit save path not exercised'
        assert target.read_bytes() == original, 'exit overwrote damaged state'
        assert not errors, errors
        print('STATE_LOAD_FAILURE_UI_OK startup, Settings, Watch Auto/edit, status and exit')
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass

tk.Tk.__init__, tk.Tk.mainloop = scaled_init, loop
os.environ.pop('MONITOR_NO_AUTOFIT', None)
try:
    namespace['run_gui'](start_hidden=False)
finally:
    tk.Tk.__init__, tk.Tk.mainloop = original_init, original_loop
