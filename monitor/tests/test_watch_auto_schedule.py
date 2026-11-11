"""Auto scheduling uses monotonic deadlines and discards edited/canceled responses."""
import copy
import queue
from pathlib import Path
import runpy
import sys
import tkinter as tk
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='watch_schedule_test')
from watch_panel import WatchPanel
from watch_keys import apply_watch_result, upsert_watch

clock = {'wall':1000.0, 'mono':500.0}
state = dict(watch_keys=[], watch_auto_enabled=False, watch_auto_minutes=1)
fixture = dict(alias='Fixture', model='fixture', api_base='https://fixture.invalid/v1', api_key='synthetic-key')
item = upsert_watch([], fixture)[0]
item = upsert_watch([item], dict(item, auto_enabled=True))[0]
state['watch_keys'] = [item]
events, calls, saves, status = queue.Queue(), [], [], []
root = tk.Tk()
root.withdraw()
ns['apply_dark_theme'](root)

def probe(*args, **kwargs):
    calls.append(args)
    return dict(ok=True, ms=1)

def pump(panel):
    if panel.batch.thread:
        panel.batch.thread.join(5)
    while not events.empty():
        panel.event(events.get_nowait())

colors = {k:v for k,v in zip(('surface','line','accent','muted','ink','btn','hover','ok','bad','warn'),
           ('#171f29','#304050','#eac070','#97a9bd','#e1e7ef','#263849','#36495b','#72cd9e','#ee8585','#e8bf73'))}
with patch('time.time', side_effect=lambda:clock['wall']), patch('time.monotonic', side_effect=lambda:clock['mono']):
    panel = WatchPanel(root, state=state, save=lambda x:saves.append(copy.deepcopy(x)), probe=probe,
                       emit=events.put, status=status.append, sources=lambda:[], colors=colors, font='Segoe UI')
    panel.pack()
    try:
        panel.tick()
        assert not calls, 'global Auto off still sent request'
        panel.auto.set(True)
        panel.save_auto()
        panel.tick()
        pump(panel)
        assert len(calls) == 1
        assert panel.deadlines[item['id']] == 560
        clock['wall'] = 9999999
        clock['mono'] = 520
        panel.tick()
        assert len(calls) == 1, 'wall clock jump bypassed monotonic deadline'
        clock['mono'] = 560
        panel.tick()
        pump(panel)
        assert len(calls) == 2
        record = state['watch_keys'][0]
        panel.tree.selection_set(record['id'])
        assert panel.store(dict(record, alias='rename only'))
        assert panel.deadlines[record['id']] == 620, 'alias edit reset backoff/deadline'
        for code in (401,403):
            record = state['watch_keys'][0]
            result = apply_watch_result(record, dict(ok=False,http_code=code,category='auth-or-quota'), now=clock['wall'], interval=60)
            assert panel.persist([result])
        assert not state['watch_keys'][0]['auto_enabled']
        panel.toggle_auto()
        assert state['watch_keys'][0]['auto_enabled']
        panel.auto.set(False)
        panel.save_auto()
        assert not state['watch_auto_enabled']
        clock['mono'] += 4000
        panel.tick()
        assert len(calls) == 2
        print('WATCH_AUTO_SCHEDULE_OK')
    finally:
        panel.close()
        root.update_idletasks()
        root.destroy()
