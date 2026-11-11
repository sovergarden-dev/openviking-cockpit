"""Live runtime revision guards use only synthetic state and blocked providers."""
import copy
import json
import os
from pathlib import Path
import runpy
import sys
import tkinter as tk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='state_revision_ui_test')
glob = ns['run_gui'].__globals__
state = glob['load_state']()
state.update(run_with_windows=False, notify_on_down=False, notify_on_failover=False, always_on_top=False)
glob['load_state'] = lambda: state
target = glob['STATE_PATH']
side_effects, errors, probes = [], [], []
glob['set_run_with_windows'] = lambda enabled: side_effects.append(enabled) or True
glob['probe_model'] = lambda *a, **k: probes.append(1)
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
        panel = next(w for w in walk(root) if w.winfo_name() == 'watch_panel')
        assert panel.store(dict(alias='Fixture', model='fixture', api_base='https://fixture.invalid/v1', api_key='synthetic-revision'))
        assert panel.store(dict(id=state['watch_keys'][0]['id'], alias='Own save two'))
        button(root, 'Cài đặt').invoke()
        root.update()
        settings = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == 'Cài đặt')
        button(settings, 'Lưu').invoke()
        root.update()
        assert not settings.winfo_exists(), 'second own-save caller kept an obsolete revision'
        button(root, 'Cài đặt').invoke()
        root.update()
        settings = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == 'Cài đặt')
        checkbox = next(w for w in walk(settings) if w.winfo_class() == 'Checkbutton' and
                        w.cget('text') == 'Khởi động cùng Windows (chạy ngầm dưới khay hệ thống)')
        checkbox.select()
        before_settings = {k: state[k] for k in ('run_with_windows', 'notify_on_down', 'notify_on_failover', 'always_on_top')}
        side_effects.clear()
        before_topmost = root.attributes('-topmost')
        panel.auto.set(True)
        state['watch_auto_enabled'] = True
        newer = json.loads(target.read_bytes())
        newer['geometry'] = '1111x777'
        newer_bytes = json.dumps(newer).encode('utf-8')
        target.write_bytes(newer_bytes)
        button(settings, 'Lưu').invoke()
        root.update()
        assert target.read_bytes() == newer_bytes, 'Settings overwrote newer disk revision'
        assert settings.winfo_exists()
        assert {k: state[k] for k in before_settings} == before_settings
        assert not side_effects and root.attributes('-topmost') == before_topmost
        assert not panel.auto.get() and not state['watch_auto_enabled'], 'revision conflict did not stop Auto'
        warning = next((w for w in walk(root) if w.winfo_name() == 'state_warning' and w.winfo_ismapped()), None)
        assert warning is not None and 'mở lại Monitor' in warning.cget('text'), 'missing persistent revision recovery banner'
        assert warning.winfo_height() >= warning.winfo_reqheight(), 'revision recovery banner is clipped'
        messages = [root.getvar(w.cget('textvariable')) for w in walk(settings)
                    if w.winfo_class() == 'Label' and w.cget('textvariable')]
        assert warning.cget('text') in messages, 'open Settings did not receive revision recovery instructions'
        original_records = copy.deepcopy(state['watch_keys'])
        assert not panel.store(dict(id=state['watch_keys'][0]['id'], alias='Must not land'))
        panel.auto_check.invoke()
        assert not panel.auto.get() and state['watch_keys'] == original_records
        button(settings, 'Thu cửa sổ vừa nội dung').invoke()
        root.update()
        assert warning.winfo_ismapped() and 'mở lại Monitor' in warning.cget('text'), 'status update erased recovery banner'
        assert target.read_bytes() == newer_bytes
        os.environ.pop('MONITOR_NO_AUTOFIT', None)
        after_callbacks = [root.tk.splitlist(root.tk.call('after', 'info', item))[0]
                           for item in root.tk.splitlist(root.tk.call('after', 'info'))]
        final_fit = [command for command in after_callbacks if command.endswith('<lambda>')]
        assert len(final_fit) == 1, 'final startup auto-fit callback missing'
        root.tk.call(final_fit[0])
        assert target.read_bytes() == newer_bytes, 'startup auto-fit overwrote external state'
        assert not state.get('geometry_autofit'), 'failed auto-fit save changed shared state'
        button(settings, 'Hủy').invoke()
        button(root, 'Cài đặt').invoke()
        root.update()
        settings = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == 'Cài đặt')
        button(settings, 'Lưu').invoke()
        assert target.read_bytes() == newer_bytes and not side_effects, 'reopened Settings bypassed save lock'
        button(settings, 'Hủy').invoke()
        root.tk.call(root.protocol('WM_DELETE_WINDOW'))
        assert target.read_bytes() == newer_bytes, 'exit overwrote external state'
        assert not probes and not errors, errors
        print('STATE_REVISION_UI_OK own saves, conflict, Settings, Auto, banner and exit')
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass


tk.Tk.__init__, tk.Tk.mainloop = scaled_init, loop
os.environ['MONITOR_NO_AUTOFIT'] = '1'
try:
    ns['run_gui'](start_hidden=False)
finally:
    tk.Tk.__init__, tk.Tk.mainloop = original_init, original_loop
