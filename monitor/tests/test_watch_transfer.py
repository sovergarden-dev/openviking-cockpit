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

        # Test bidirectional transfer: Watch -> Reserve (→ Dự trữ)
        status_msgs = []
        orig_status = panel.status
        panel.status = lambda m: (status_msgs.append(m), orig_status(m))

        watch_rec = dict(model='fixture/watch-model', api_base='https://watch.invalid/v1',
                         api_key='synthetic-watch-key', alias='Omega')
        assert panel.store(watch_rec), f"store failed: {panel.last_error}"
        root.update()
        watch_id = next(item['id'] for item in state['watch_keys'] if item.get('model') == 'fixture/watch-model')
        panel.tree.selection_set(watch_id)
        to_spare_btn = next(w for w in walk(panel) if w.winfo_class() == 'Button' and w.cget('text') == '→ Dự trữ')
        to_spare_btn.invoke()
        root.update()
        new_spare = next((s for s in state['spare_models'] if s.get('model') == 'fixture/watch-model'), None)
        assert new_spare is not None, 'watch record was not saved to spare_models'
        assert new_spare['api_key'] == 'synthetic-watch-key'
        assert '(từ theo dõi Omega)' in new_spare['note']
        assert not set(new_spare) & {'id', 'rev', 'last_probe', 'fail_streak', 'cooldown_until', '_enc', '_sha', 'auto_enabled'}
        assert any('Đã lưu' in m and 'watch-model' in m for m in status_msgs), f"success message missing: {status_msgs}"

        # Duplicate detection: saving again with same key must report duplicate and not increase count
        spares_count_before = len(state['spare_models'])
        to_spare_btn = next(w for w in walk(panel) if w.winfo_class() == 'Button' and w.cget('text') == '→ Dự trữ')
        to_spare_btn.invoke()
        root.update()
        assert len(state['spare_models']) == spares_count_before, 'duplicate watch-to-spare was created'
        assert any('đã có trong Dự trữ' in m for m in status_msgs), f'unexpected duplicate status: {status_msgs}'

        # Independence: mutating watch key must not affect the saved spare
        assert panel.store(dict(id=watch_id, model='fixture/watch-model', api_base='https://watch.invalid/v1',
                                api_key='synthetic-mutated-watch-key', alias='Omega'))
        root.update()
        re_fetched_spare = next(s for s in state['spare_models'] if s.get('model') == 'fixture/watch-model')
        assert re_fetched_spare['api_key'] == 'synthetic-watch-key', 'mutating watch key leaked into spare'

        # DPAPI-locked / empty key rejection
        locked_id = 'watch-locked-fixture'
        locked_rec = dict(id=locked_id, model='fixture/locked-model', api_base='https://watch.invalid/v1',
                          api_key='', _dpapi_locked=True, alias='Locked', auto_enabled=False)
        state['watch_keys'].append(locked_rec)
        panel.render()
        panel.tree.selection_set(locked_id)
        to_spare_btn = next(w for w in walk(panel) if w.winfo_class() == 'Button' and w.cget('text') == '→ Dự trữ')
        to_spare_btn.invoke()
        root.update()
        assert not any(s.get('model') == 'fixture/locked-model' for s in state['spare_models']), 'locked watch key was saved to spares'
        assert any('khóa DPAPI' in m for m in status_msgs), f'unexpected locked status: {status_msgs}'
        state['watch_keys'].pop()
        panel.render()

        # Verify disk encryption of the newly transferred spare
        persisted_spares = json.loads((conf.parent / 'monitor/monitor.json').read_text(encoding='utf-8'))['spare_models']
        saved_spare = next(s for s in persisted_spares if s.get('model') == 'fixture/watch-model')
        assert saved_spare['api_key'].startswith('dpapi:'), 'transferred spare was not encrypted with DPAPI on disk'
        assert 'synthetic-watch-key' not in json.dumps(persisted_spares), 'raw key leaked in monitor.json'

        # Verify Kiểm định button exists and invokes audit hook
        audit_calls = []
        panel.to_audit = lambda rec: audit_calls.append(rec)
        panel.tree.selection_set(watch_id)
        audit_btn = next(w for w in walk(panel) if w.winfo_class() == 'Button' and w.cget('text') == 'Kiểm định')
        audit_btn.invoke()
        root.update()
        assert len(audit_calls) == 1 and audit_calls[0]['id'] == watch_id, f'audit button failed: {audit_calls}'

        # Verify on_auto_disabled hook on 2 consecutive 401/403
        disabled_calls = []
        panel.on_auto_disabled = lambda rec: disabled_calls.append(rec)
        # Ensure watch_key has auto_enabled=True and auth_fail_streak=1
        rec = next(item for item in panel.items() if item['id'] == watch_id)
        panel.store(dict(rec, auto_enabled=True, auth_fail_streak=1))
        root.update()
        # Fire two consecutive 401 results to reach the streak threshold of 2
        panel.batch.stop.clear()
        run_id = panel.batch.run_id
        curr_rec = next(item for item in panel.items() if item['id'] == watch_id)
        # 1st 401
        panel.event(('watch_result', run_id, watch_id, curr_rec['rev'], {'ok': False, 'http_code': 401, 'text': '401 Unauthorized', 'ms': 100}))
        root.update()
        assert len(disabled_calls) == 0, 'should not disable on 1st 401'
        # 2nd 401
        curr_rec = next(item for item in panel.items() if item['id'] == watch_id)
        panel.event(('watch_result', run_id, watch_id, curr_rec['rev'], {'ok': False, 'http_code': 401, 'text': '401 Unauthorized', 'ms': 100}))
        root.update()
        assert len(disabled_calls) == 1, f'expected 1 on_auto_disabled call, got {len(disabled_calls)}'
        assert disabled_calls[0]['id'] == watch_id
        assert disabled_calls[0]['auto_disabled_reason']

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
