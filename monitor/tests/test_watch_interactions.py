"""Row Auto gestures are unambiguous and cannot open an edit dialog."""
import copy
from pathlib import Path
import sys
import time
import tkinter as tk

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from watch_panel import WatchPanel

root = tk.Tk()
root.geometry('1020x430')
state = dict(watch_keys=[], watch_auto_enabled=False)
logs, requests = [], []
colors = dict(surface='#171d26', line='#303b49', accent='#eab84b', muted='#9aa7b8',
              ink='#edf2f7', btn='#263242', hover='#304056', ok='#79d8b0', bad='#ff9494', warn='#eab84b')
panel = WatchPanel(root, state=state, save=lambda _: None, probe=lambda *a, **k: requests.append(1),
                   emit=lambda _: None, status=logs.append, sources=lambda: [], colors=colors, font='Segoe UI')
panel.pack(fill='both', expand=True)
try:
    assert panel.store(dict(alias='Gesture', model='fixture/model', api_base='https://fixture.invalid/v1', api_key='synthetic'))
    root.update()
    row = state['watch_keys'][0]['id']
    panel.tree.selection_set(row)
    box = panel.tree.bbox(row, 'auto')
    assert box, 'Auto cell not visible'
    x, y = box[0] + box[2] // 2, box[1] + box[3] // 2
    edits = []
    panel.edit = lambda **kwargs: edits.append(kwargs)
    for tick in (1000, 1100):
        panel.tree.event_generate('<ButtonPress-1>', x=x, y=y, time=tick)
        panel.tree.event_generate('<ButtonRelease-1>', x=x, y=y, time=tick + 30)
        root.update()
    assert not edits, 'double-clicking Auto opened editor'
    assert state['watch_keys'][0]['auto_enabled'], 'double-clicking Auto toggled twice'
    assert panel.tree.set(row, 'auto') == 'Chờ tổng', 'enabled row falsely implies active Auto'
    assert 'Chờ Auto tổng' in panel.detail.get()
    panel.auto.set(True)
    panel.save_auto()
    assert panel.tree.set(row, 'auto') == 'Bật'
    assert not requests, 'Auto gesture sent a probe with global Auto off'
    panel.auto.set(False)
    panel.save_auto()
    state['watch_keys'][0]['last_probe'] = dict(ok=True, text='OK', at=time.time() - 3600, ms=12)
    panel.tick()
    assert panel.tree.set(row, 'status') == 'Cũ · OK', 'old success still appears current'
    assert 'stale' in panel.tree.item(row, 'tags')
    assert state['watch_keys'][0]['last_probe']['ok'] is True, 'freshness rewrote probe evidence'
    assert not requests
    print('WATCH_INTERACTIONS_OK')
finally:
    panel.close()
    root.update_idletasks()
    root.destroy()
