"""Backup failure keeps Settings and Watch state transactional in the real GUI."""
import copy
from pathlib import Path
import runpy
import sys
import tkinter as tk
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='state_backup_ui_test')
glob = ns['run_gui'].__globals__
state = glob['load_state']()
glob['load_state'] = lambda: state
side_effects, errors = [], []
glob['set_run_with_windows'] = lambda enabled: side_effects.append(enabled)
original_loop = tk.Tk.mainloop


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
        target = glob['STATE_PATH']
        before_bytes = target.read_bytes()
        before_state = copy.deepcopy(state)
        writer = Mock()
        with patch.dict(glob, apply_restricted_file_acl=Mock(return_value=False), safe_atomic_write_json=writer):
            button(root, 'Cài đặt').invoke()
            root.update()
            settings = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == 'Cài đặt')
            checkbox = next(w for w in walk(settings) if w.winfo_class() == 'Checkbutton' and
                            w.cget('text') == 'Khởi động cùng Windows (chạy ngầm dưới khay hệ thống)')
            checkbox.select()
            button(settings, 'Lưu').invoke()
            root.update()
            assert settings.winfo_exists(), 'backup failure closed Settings'
            assert state == before_state and not side_effects, 'backup failure applied candidate settings'
            panel = next(w for w in walk(root) if w.winfo_name() == 'watch_panel')
            assert not panel.store(dict(alias='Fixture', model='fixture',
                                        api_base='https://fixture.invalid/v1', api_key='synthetic-backup-ui'))
            assert state == before_state, 'backup failure applied Watch record'
            assert target.read_bytes() == before_bytes, 'backup failure changed disk state'
        writer.assert_not_called()
        button(settings, 'Hủy').invoke()
        assert not errors, errors
        print('STATE_BACKUP_UI_OK Settings, Watch and runtime preserved on backup failure')
    finally:
        root.destroy()


tk.Tk.mainloop = loop
try:
    ns['run_gui'](start_hidden=False)
finally:
    tk.Tk.mainloop = original_loop
