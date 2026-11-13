"""Reserve-to-watch copy is explicit, independent and never probes or edits slots."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tkinter as tk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='watch_transfer_test')
glob = ns['run_gui'].__globals__
state = glob['load_state']()
source = dict(model='fixture/zeta', api_base='https://fixture.invalid/v1',
              api_key='synthetic-transfer', note='Original reserve note', auto_enabled=True,
              last_probe={'ok': True, 'text': 'OK', 'at': 1})
state.update(watch_keys=[], watch_auto_enabled=False, spare_models=[source])
spares_before = copy.deepcopy(state['spare_models'])
glob['load_state'] = lambda: state
calls, errors = [], []
glob['probe_model'] = lambda *a, **k: calls.append('probe')
glob['inherit_key'] = lambda *a, **k: (_ for _ in ()).throw(AssertionError('implicit key inheritance'))
conf = Path(os.environ['USERPROFILE']) / '.openviking/ov.conf'
conf_before = hashlib.sha256(conf.read_bytes()).digest()


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def loop(root, *args):
    root.report_callback_exception = lambda *exc: errors.append(exc)
    from watch_panel import WatchPanel
    panel = next(w for w in walk(root) if isinstance(w, WatchPanel))
    try:
        root.update()
        book = next(w for w in walk(root) if w.winfo_class() == 'TNotebook')
        spare = next(w for w in walk(root) if 'reservetable' in w.winfo_name())
        menu = next(w for w in walk(root) if w.winfo_class() == 'Menu' and
                    any(w.entrycget(i, 'label') == 'Đưa vào slot' for i in range(w.index('end') + 1)))
        labels = [menu.entrycget(i, 'label') for i in range(menu.index('end') + 1)]
        assert 'Đưa sang Theo dõi' in labels, 'reserve menu has no watch transfer'
        transfer_index = labels.index('Đưa sang Theo dõi')
        buttons = [w for w in walk(spare.master) if w.winfo_class() == 'Button' and w.cget('text') == 'Đưa sang Theo dõi']
        assert len(buttons) == 1, 'reserve needs a visible transfer button'
        book.select(1)
        spare.selection_set(0)
        menu.invoke(transfer_index)
        root.update()
        assert book.index(book.select()) == 0, 'transfer did not reveal watch editor'
        editor = next(w for w in walk(root) if w.winfo_class() == 'Toplevel')
        fields = {w.winfo_name(): w for w in walk(editor) if w.winfo_class() in ('TEntry', 'TCombobox')}
        assert fields['watch_model'].winfo_class() == 'TCombobox', 'watch_model must be a Combobox'
        assert fields['watch_model'].get() == source['model']
        assert fields['watch_api_key'].get() == 'synthetic-transfer'
        assert fields['watch_api_key'].cget('show') == '•'
        assert state['watch_keys'] == [], 'opening transfer committed before confirmation'
        next(w for w in walk(editor) if w.winfo_class() == 'Button' and w.cget('text') == 'Lưu').invoke()
        root.update()
        assert len(state['watch_keys']) == 1
        copied = state['watch_keys'][0]
        assert not copied['auto_enabled'] and not state['watch_auto_enabled']
        assert copied['api_key'] == source['api_key'] and copied['model'] == source['model']
        assert 'last_probe' not in copied, 'reserve test result leaked into fresh watch'
        assert state['spare_models'] == spares_before, 'copy mutated the source reserve'
        persisted = json.loads((conf.parent / 'monitor/monitor.json').read_text(encoding='utf-8'))
        assert persisted['watch_keys'][0]['api_key'].startswith('dpapi:')
        assert 'synthetic-transfer' not in json.dumps(persisted)
        panel.tree.selection_set(copied['id'])
        assert panel.store(dict(id=copied['id'], alias='Independent', api_key='synthetic-new-key'))
        assert state['spare_models'] == spares_before
        for i in range(6):
            assert panel.store(dict(model='fixture/fill', api_base=source['api_base'], api_key='synthetic-fill', alias=str(i)))
        book.select(1)
        buttons[0].invoke()
        root.update()
        assert not any(w.winfo_class() == 'Toplevel' for w in walk(root)), 'eighth watch opened an editor'
        assert len(state['watch_keys']) == 7
        assert panel.persist([])
        for unavailable in (dict(source, _dpapi_locked=True, api_key=''), dict(source, api_key='')):
            state['spare_models'] = [unavailable]
            spare.render(state['spare_models'])
            spare.selection_set(0)
            buttons[0].invoke()
            root.update()
            assert not any(w.winfo_class() == 'Toplevel' for w in walk(root)), 'unreadable source was accepted'
            assert not state['watch_keys']
        assert not calls, 'copy sent a provider request'
        assert hashlib.sha256(conf.read_bytes()).digest() == conf_before
        assert not errors, [type(e[1]).__name__ for e in errors]
        print('WATCH_TRANSFER_OK')
    finally:
        panel.close()
        root.update_idletasks()
        root.destroy()


original_loop = tk.Tk.mainloop
tk.Tk.mainloop = loop
try:
    ns['run_gui'](start_hidden=False)
finally:
    tk.Tk.mainloop = original_loop
