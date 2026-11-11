"""Sequential watch batches reject late, edited and canceled results."""
import queue
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import watch_keys

assert hasattr(watch_keys, 'WatchBatch'), 'Missing bounded WatchBatch worker'
WatchBatch = watch_keys.WatchBatch
items = [watch_keys.upsert_watch([], {'model':'m','api_base':'https://fixture.invalid/v1',
                                      'api_key':f'synthetic-{i}'})[0] for i in range(2)]
for item in items:
    item['auto_enabled'] = True
entered, release = threading.Event(), threading.Event()
events = queue.Queue()
calls = []

def probe(model, base, key, **kwargs):
    assert kwargs['timeout'] == 20.0
    assert kwargs['max_tokens'] == 64
    calls.append(key)
    entered.set()
    assert release.wait(5), 'test worker barrier timed out'
    return {'ok':True,'ms':1}

batch = WatchBatch()
batch.sync(items)
assert batch.start(items, probe, events.put, auto=True)
assert entered.wait(5)
assert not batch.start(items, probe, events.put), 'overlapping request worker started'
revision = items[0]['rev']
items[0]['rev'] += 1
items[1]['rev'] += 1
batch.sync(items)
release.set()
batch.thread.join(5)
assert not batch.thread.is_alive()
assert not batch.start(items, probe, events.put), 'worker restarted before queued results were consumed'
messages = list(events.queue)
assert len(calls) == 1, 'edited second watch still sent old credential'
result_event = next(e for e in messages if e[0] == 'watch_result')
_, run_id, watch_id, rev, result = result_event
assert rev == revision and not batch.accepts(run_id, watch_id, rev)
batch.complete(run_id)

entered.clear()
release.clear()
assert batch.start(items, probe, events.put)
assert entered.wait(5)
batch.cancel()
assert not batch.start(items, probe, events.put), 'cancel let a second worker overlap'
release.set()
batch.thread.join(5)
assert not batch.accepts(batch.run_id - 1, items[0]['id'], items[0]['rev'])

calls.clear()
assert batch.start(items, probe, events.put)
batch.thread.join(5)
assert len(calls) == 2, 'manual batch is not sequential and complete'
messages = list(events.queue)
latest = [e for e in messages if e[0] == 'watch_result' and e[1] == batch.run_id]
assert len(latest) == 2 and all(batch.accepts(e[1], e[2], e[3]) for e in latest)
batch.complete(batch.run_id)
batch.sync([])
assert not batch.accepts(latest[0][1], latest[0][2], latest[0][3]), 'deleted watch accepted late result'
print('WATCH_BATCH_OK')
