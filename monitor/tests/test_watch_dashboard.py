"""Two tabs keep watch operations independent of runtime slots and reserves."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import time
import tkinter as tk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='watch_dashboard_test')
glob = ns['run_gui'].__globals__
state = glob['load_state']()
state.update(geometry='880x800', watch_keys=[], watch_auto_enabled=False)
glob['load_state'] = lambda: state
conf_path = Path(os.environ['USERPROFILE']) / '.openviking/ov.conf'
before = hashlib.sha256(conf_path.read_bytes()).hexdigest()
spares_before = copy.deepcopy(state['spare_models'])
calls, errors = [], []

def probe(model, base, key, **kwargs):
    calls.append((model, base, key, kwargs))
    return {'ok': True, 'ms': 12}

glob['probe_model'] = probe
original_loop = tk.Tk.mainloop

def loop(root, *args):
    root.report_callback_exception = lambda *exc: errors.append(exc)
    def walk(widget):
        yield widget
        for child in widget.winfo_children():
            yield from walk(child)
    try:
        root.update()
        notebook = next((w for w in walk(root) if w.winfo_class() == 'TNotebook'), None)
        assert notebook is not None, 'DỰ TRỮ has not moved to a separate tab'
        assert [notebook.tab(t, 'text') for t in notebook.tabs()] == ['Tổng quan', 'Dự trữ']
        assert not any(w.winfo_class() == 'Panedwindow' for w in walk(root))
        from watch_panel import WatchPanel
        panel = next(w for w in walk(root) if isinstance(w, WatchPanel))
        assert panel.winfo_ismapped() and not calls
        assert not any(w.winfo_class() in ('Entry', 'TEntry') for w in walk(panel)), 'watch panel has a search field'
        fixture = dict(alias='Fixture', model='fixture/model', api_base='https://fixture.invalid/v1', api_key='synthetic-watch')
        for i in range(7):
            assert panel.store(dict(fixture, alias=f'Key {i}'))
        assert len(state['watch_keys']) == 7
        assert not panel.store(fixture), 'eighth key accepted'
        first = state['watch_keys'][0]
        panel.tree.selection_set(first['id'])
        assert panel.store(dict(first, alias='Renamed'))
        assert state['watch_keys'][0]['alias'] == 'Renamed'
        panel.toggle_auto()
        assert state['watch_keys'][0]['auto_enabled'] and not state['watch_auto_enabled']
        assert not calls, 'saving or toggling row Auto sent a provider request'
        old_save = panel.save
        def fail_save(candidate):
            raise RuntimeError('synthetic save failure')
        panel.save = fail_save
        old = copy.deepcopy(state['watch_keys'])
        assert not panel.store(dict(state['watch_keys'][0], alias='Must not persist'))
        assert state['watch_keys'] == old, 'save failure changed in-memory state'
        panel.save = old_save
        panel.probe_selected()
        panel.batch.thread.join(5)
        for _ in range(8):
            root.update()
            time.sleep(.08)
        assert len(calls) == 1 and calls[0][2] == 'synthetic-watch'
        assert calls[0][3] == {'timeout':20.0, 'max_tokens':64}
        assert state['watch_keys'][0]['last_probe']['ok']
        panel.edit()
        root.update()
        editor = next(w for w in walk(root) if w.winfo_class() == 'Toplevel')
        key_entry = next(w for w in walk(editor) if w.winfo_name() == 'watch_api_key')
        assert key_entry.cget('show') == '•'
        alias_entry = next(w for w in walk(editor) if w.winfo_name() == 'watch_alias')
        alias_entry.delete(0, 'end')
        alias_entry.insert(0, 'Renamed while probing')
        panel.probe = lambda *_args, **_kwargs: {'ok': False, 'http_code': 401, 'category': 'auth-or-quota'}
        for _ in range(2):
            panel.probe_selected()
            panel.batch.thread.join(5)
            for _ in range(8):
                root.update()
                time.sleep(.08)
        disabled = copy.deepcopy(state['watch_keys'][0])
        assert not disabled['auto_enabled'] and disabled['auth_fail_streak'] == 2
        save_button = next(w for w in walk(editor) if w.winfo_class() == 'Button' and w.cget('text') == 'Lưu')
        save_button.invoke()
        updated = state['watch_keys'][0]
        assert updated['alias'] == 'Renamed while probing'
        assert not updated['auto_enabled'], 'stale editor silently re-enabled Auto'
        assert updated['auth_fail_streak'] == disabled['auth_fail_streak']
        assert updated['auto_disabled_reason'] == disabled['auto_disabled_reason']
        assert updated['last_probe'] == disabled['last_probe']
        notebook.select(1)
        root.update()
        assert not panel.winfo_ismapped()
        spare = next(w for w in walk(root) if 'reservetable' in w.winfo_name())
        assert spare.winfo_ismapped() and spare.winfo_width() >= root.winfo_width() - 90
        labels = [str(w.cget('text')) for w in walk(spare.master) if w.winfo_class() == 'Checkbutton']
        assert not any('Auto' in text for text in labels), labels
        foot = next(w for w in walk(root) if w.winfo_name() == 'shared_status')
        assert foot.master is root and foot.winfo_ismapped(), 'shared status hidden with dashboard tab'
        assert hashlib.sha256(conf_path.read_bytes()).hexdigest() == before
        assert state['spare_models'] == spares_before
        assert not errors, [str(e[1]) for e in errors]
        saved = json.loads((conf_path.parent / 'monitor/monitor.json').read_text())
        assert len(saved['watch_keys']) == 7 and all(s['api_key'].startswith('dpapi:') for s in saved['watch_keys'])
        print('WATCH_DASHBOARD_OK')
    finally:
        if 'panel' in locals():
            panel.close()
        root.update_idletasks()
        root.destroy()

tk.Tk.mainloop = loop
try:
    ns['run_gui'](start_hidden=False)
finally:
    tk.Tk.mainloop = original_loop
