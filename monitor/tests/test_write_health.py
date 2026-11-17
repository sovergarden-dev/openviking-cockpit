"""Read-only write-pipeline telemetry; no live API or configuration writes."""
import ast
import json
import math
import os
import tempfile
import time
import urllib.parse
import threading
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'openviking-monitor.pyw'
tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
ns = dict(time=time, Path=Path, os=os, urllib=urllib, math=math, _WRITE_HEALTH_LOCK=threading.Lock(),
          _WRITE_HEALTH_TTL_S=30.0, _WRITE_HEALTH_BUDGET_S=6.0, _WRITE_HEALTH_STATS_BUDGET_S=3.0,
          _WRITE_HEALTH_MAX_BYTES=4 * 1024 * 1024, _WRITE_HEALTH_STATE={},
          OV_TASKS='tasks', OV_MEMORY_STATS='stats', HOME=Path(tempfile.gettempdir()),
          _SNAPSHOT_LOCK=threading.Lock(), _SNAPSHOT_GEN={'n': 0}, threading=threading)
names = {'summarize_write_health', 'write_health_text', 'collect_write_health', 'scan_commit_tasks',
         'scan_pending_markers', 'write_health_fetch', 'invalidate_write_health', 'telemetry_publishable',
         'accept_snapshot', 'next_snapshot_generation', '_write_health_lock_state'}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0)] + nodes, type_ignores=[])), str(SOURCE), 'exec'), ns)
assert 'summarize_write_health' in ns, 'write-pipeline summary is missing'
summary = ns['summarize_write_health']
text = ns['write_health_text']

def tasks(items, more=False):
    return 200, {'status': 'ok', 'result': {'items': items, 'has_more': more, 'next_cursor': 'fixture' if more else None}}

with tempfile.TemporaryDirectory() as root:
    directory = Path(root) / 'pending_sessions'
    directory.mkdir()
    health = summary(tasks([
        {'task_type': 'session_commit', 'task_id': 'a', 'status': 'completed', 'created_at': 100, 'updated_at': 140, 'result': {'memories_extracted': {'memory_write': 3}}},
        {'task_type': 'session_commit', 'task_id': 'b', 'status': 'failed', 'created_at': 200, 'updated_at': 220, 'error': 'SECRET_DO_NOT_EXPORT'},
        {'task_type': 'session_commit', 'task_id': 'c', 'status': 'running', 'created_at': 500},
    ]), (200, {'status': 'ok', 'result': {'total_memories': 12}}), directory, now=1500)
    assert health['counts'] == {'pending': 0, 'running': 1, 'cancelling': 0, 'completed': 1, 'failed': 1, 'cancelled': 0}
    assert health['last_success'] == 140
    assert health['oldest_active_age_s'] == 1000
    assert health['marker_count'] == 0
    assert health['total_memories'] == 12
    assert health['alert'] and health['tone'] == 'bad'
    assert 'SECRET' not in json.dumps(health)
    assert 'backlog' in text(health) and 'không' in text(health)
    empty = summary(tasks([]), (503, {}), directory, now=1500)
    assert empty['last_success'] is None and empty['total_memories'] is None
    assert empty['tone'] == 'warn' and not empty['alert']
    unknown = summary((503, {}), (200, {'result': {'total_memories': 12}}), directory, now=1500)
    assert unknown['counts'] is None and unknown['tone'] == 'warn'
    assert 'chưa rõ' in text(unknown)
    truncated = summary(tasks([], True), (200, {'result': {'total_memories': 12}}), directory, now=1500)
    assert truncated['has_more'] and 'mẫu' in text(truncated)
    assert truncated['tone'] == 'warn', 'truncated task window cannot prove a healthy write pipeline'
    marker = directory / 'fixture.json'
    marker.write_text('{}', encoding='utf-8')
    os.utime(marker, (1000, 1000))
    marked = summary(tasks([]), (200, {'result': {'total_memories': 12}}), directory, now=1500)
    assert marked['marker_count'] == 1 and marked['oldest_marker_age_s'] == 500
    malformed = summary((200, {'result': {'items': [{}], 'has_more': False}}), (200, {'result': {}}), directory, now=1500)
    assert malformed['counts'] is None and malformed['tone'] == 'warn'
    missing_page = summary((200, {'result': {'items': []}}), (200, {'result': {'total_memories': 12}}), directory, now=1500)
    assert missing_page['counts'] is None and missing_page['tone'] == 'warn'
    failed_sample = summary(tasks([{'task_id': 'a', 'task_type': 'session_commit', 'status': 'completed', 'created_at': 0, 'updated_at': 140}]), (200, {'result': {'total_memories': 12}}), directory, now=1500)
    assert failed_sample['tone'] == 'ok' and failed_sample['alert'] is None
    assert 'lỗi' in text(health) and 'hủy' in text(health), 'cancelled tasks must stay visible'
    absent = summary(tasks([]), (200, {'result': {'total_memories': 12}}), Path(root) / 'absent', now=1500)
    assert absent['marker_count'] is None and absent['marker_state'] == 'missing'
    assert health['marker_state'] == 'observed'
    assert health['last_attempt'] == 500
    assert '1 trang' in text(health) and 'Quan sát' in text(health)
    no_age = summary(tasks([{'task_type': 'session_commit', 'task_id': 'timeless', 'status': 'running'}]), (200, {'result': {'total_memories': 12}}), directory, now=1500)
    assert no_age['tone'] == 'warn' and no_age['age_unknown'] == 1
    future = summary(tasks([{'task_type': 'session_commit', 'task_id': 'future', 'status': 'running', 'created_at': float('inf')}]), (200, {'result': {'total_memories': 12}}), directory, now=1500)
    assert future['tone'] == 'warn' and future['oldest_active_age_s'] is None
    assert 'Lần thử task' in text(health) and 'Tuổi từ lúc tạo' in text(health)

    # OpenViking TaskRecord.to_dict(): created_at/updated_at are required finite epoch floats; total_memories is a non-negative non-bool int.
    ok_row = {'task_id': 's', 'task_type': 'session_commit', 'status': 'completed', 'created_at': 100, 'updated_at': 140}
    for bad_total in (True, False, -3, '12', 12.5, None, float('nan')):
        h = summary(tasks([ok_row]), (200, {'result': {'total_memories': bad_total}}), directory, now=1500)
        assert h['total_memories'] is None and h['stats_issue'] == 'schema', bad_total
        assert h['tone'] == 'warn', f'stats {bad_total!r} cannot look healthy'
        assert 'sai schema' in text(h), bad_total
    assert summary(tasks([ok_row]), (503, {}), directory, now=1500)['stats_issue'] == 'unavailable'
    assert summary(tasks([ok_row]), (200, {'result': {'total_memories': 0}}), directory, now=1500)['total_memories'] == 0
    optional_null = summary(tasks([dict(ok_row, processing_seconds=None, stage=None, error=None, resource_id=None)]),
                            (200, {'result': {'total_memories': 9}}), directory, now=1500)
    assert optional_null['timestamp_invalid'] == 0 and optional_null['tone'] == 'ok', 'optional nulls are valid per schema'
    for bad_ts in ('140', True, float('nan'), float('inf'), 10**12, None, []):
        h = summary(tasks([dict(ok_row, updated_at=bad_ts)]), (200, {'result': {'total_memories': 9}}), directory, now=1500)
        assert h['timestamp_invalid'] == 1 and h['tone'] == 'warn', bad_ts
        assert h['last_success'] is None, bad_ts
    h = summary(tasks([dict(ok_row, created_at='100')]), (200, {'result': {'total_memories': 9}}), directory, now=1500)
    assert h['timestamp_invalid'] == 1 and h['tone'] == 'warn' and h['last_attempt'] is None
    h = summary(tasks([dict(ok_row, created_at=500, updated_at=400)]), (200, {'result': {'total_memories': 9}}), directory, now=1500)
    assert h['timestamp_invalid'] == 1 and h['tone'] == 'warn', 'updated_at before created_at is malformed'
    h = summary(tasks([{'task_id': 's', 'task_type': 'session_commit', 'status': 'completed'}]),
                (200, {'result': {'total_memories': 9}}), directory, now=1500)
    assert h['timestamp_invalid'] == 1 and h['tone'] == 'warn' and h['last_success'] is None
    assert 'mốc thời gian' in text(h)
print('WRITE_HEALTH_SUMMARY_OK')

# --- incidents stay scoped to the observed sample: unknown/stale never resolves one
import sys
sys.path.insert(0, str(SOURCE.parent))
from openviking_monitor_notification import NotificationController
controller = NotificationController(retry_cooldown=60, max_retries=2)
state = {'notify_on_down': True}
snapshot = {'ov_up': True, 'watchdog_ok': True, 'write_health': {'alert': 'Extraction failed', 'tone': 'bad'}}
events = controller.evaluate(None, snapshot, state, now=100, now_mono=10)
assert [e['kind'] for e in events] == ['write_path'], events
controller.acknowledge_delivery('write_path', False)
assert controller.evaluate(None, snapshot, state, now=110, now_mono=20) == []
assert controller.catchup_pending(state, now=170, now_mono=80)[0]['kind'] == 'write_path'
controller.acknowledge_delivery('write_path', True)
assert controller.evaluate(None, snapshot, state, now=180, now_mono=90) == []
controller.evaluate(None, dict(snapshot, write_health={'alert': None, 'tone': 'ok'}), state, now=200, now_mono=110)
assert controller.evaluate(None, snapshot, state, now=210, now_mono=120)[0]['kind'] == 'write_path'
controller.acknowledge_delivery('write_path', True)
changing = dict(snapshot, write_health={'alert': 'Extraction chờ/chạy 16 phút', 'tone': 'bad'})
assert controller.evaluate(None, changing, state, now=220, now_mono=130) == [], 'same write incident must not re-notify on age/count changes'
controller.evaluate(None, dict(snapshot, write_health={'alert': None, 'tone': 'warn'}), state, now=230, now_mono=140)
assert controller.incidents['write_path']['active'], 'unknown must not resolve an incident'
controller.evaluate(None, dict(snapshot, write_health={'alert': None, 'tone': 'warn', 'stale': True}), state, now=240, now_mono=150)
assert controller.incidents['write_path']['active'], 'stale must not resolve an incident'
print('WRITE_HEALTH_NOTIFICATION_OK')

src = SOURCE.read_text(encoding='utf-8')
assert '"write_health": collect_write_health(' in src, 'collector must feed the real snapshot'
assert 'write_health_text(snap.get("write_health")' in src, 'ops panel must display write health'
assert 'OV_TASKS =' in src and 'pagination=cursor' in src

run_ns = dict(time=time, short_model=lambda s: s or '—', watchdog_ok=lambda s: True)
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'sentence')
exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(SOURCE), 'exec'), run_ns)
base = {'ov_up': True, 'ollama_up': True, 'gateway_up': True,
        'queue': {}, 'conf': {}, 'write_health': {'tone': 'bad', 'alert': 'fixture extraction failed'}}
assert run_ns['sentence'](base) == ('fixture extraction failed', 'bad')
base['write_health'] = {'tone': 'warn', 'alert': None}
assert run_ns['sentence'](base)[1] == 'warn', 'unknown extraction cannot be healthy'

scanner = ns['scan_commit_tasks']
def row(task_id, status='completed'):
    return {'task_id': task_id, 'task_type': 'session_commit', 'status': status, 'created_at': 100, 'updated_at': 140}

# --- P1-B: scan budget is re-checked after request+read+parse, including the last page
def scan_row(n, status='completed'):
    return {'task_id': f'r{n}', 'task_type': 'session_commit', 'status': status, 'created_at': 100, 'updated_at': 140}
page1 = tasks([scan_row(n) for n in range(200)], True)
page2 = tasks([scan_row(999)])
ns['_WRITE_HEALTH_BUDGET_S'] = 0.05
def slow_second_page(url, timeout, **kwargs):
    if 'cursor=' not in url:
        return page1
    time.sleep(0.08)
    return page2
ns['http_json'] = slow_second_page
slow_reply = scanner()
assert slow_reply[1]['result']['scan_issue'] == 'budget', slow_reply[1]['result']['scan_issue']
assert slow_reply[1]['result']['pages'] == 1 and len(slow_reply[1]['result']['items']) == 200
with tempfile.TemporaryDirectory() as root:
    over = summary(slow_reply, (200, {'result': {'total_memories': 12}}), Path(root))
    assert over['coverage'] == 'partial' and over['tone'] == 'warn'
    assert 'Phạm vi chưa đủ' in text(over)
ns['http_json'] = lambda url, timeout, **kwargs: (time.sleep(0.08), tasks([]))[1]
last_page = scanner()
assert last_page[1]['result']['scan_issue'] == 'budget', 'over-budget last page cannot count as a full scan'
assert last_page[1]['result']['pages'] == 0
ns['_WRITE_HEALTH_BUDGET_S'] = 6.0
print('WRITE_HEALTH_SCAN_BUDGET_OK')

# --- P1-A wiring: multi-page cursor scan still detects a duplicate id with a changed status
page_a = tasks([row(str(i)) for i in range(200)], True)
page_b = tasks([row('199'), row('hidden-failure', 'failed')])
replies = iter([page_a, page_b])
seen = []
ns['http_json'] = lambda url, timeout, **kw: (seen.append(url) or next(replies))
reply = scanner()
assert len(seen) == 2 and 'cursor=fixture' in seen[1]
assert reply[1]['result']['pages'] == 2 and len(reply[1]['result']['items']) == 201
with tempfile.TemporaryDirectory() as root:
    h = summary(reply, (200, {'result': {'total_memories': 12}}), Path(root))
    assert h['counts']['failed'] == 1 and h['tone'] == 'bad'
    replies = iter([page_a, (503, {})])
    partial = scanner()
    h = summary(partial, (200, {'result': {'total_memories': 12}}), Path(root))
    assert h['counts']['completed'] == 200 and h['tone'] == 'warn'
    assert h['coverage'] == 'partial' and h['pages'] == 1
    replies = iter([page_a, page_a])
    h = summary(scanner(), (200, {'result': {'total_memories': 12}}), Path(root))
    assert h['tone'] == 'warn' and h['coverage'] == 'partial'
    replies = iter([tasks([row('alien', 'new-status')])])
    h = summary(scanner(), (200, {'result': {'total_memories': 12}}), Path(root))
    assert h['unknown_count'] == 1 and h['tone'] == 'warn'
print('WRITE_HEALTH_CURSOR_OK')

# --- P1-B: telemetry responses are size-bounded before parse
import http.server
import socketserver
import urllib.request
class BigBody(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b'{"result": "' + b'x' * 5000 + b'"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *args):
        pass
server = socketserver.TCPServer(('127.0.0.1', 0), BigBody)
threading.Thread(target=server.serve_forever, daemon=True).start()
http_ns = dict(json=json, urllib=urllib, ssl_context=lambda: None,
               classify_endpoint=lambda url: {'type': 'ok'},
               verification_http_json=lambda *a, **k: (None, 'blocked'),
               http_fail_text=lambda exc: f'fail:{type(exc).__name__}')
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'http_json')
exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(SOURCE), 'exec'), http_ns)
big_url = f'http://127.0.0.1:{server.server_address[1]}/big'
code, body = http_ns['http_json'](big_url, timeout=2, max_bytes=500)
assert code is None and 'too large' in str(body), (code, body)
code, body = http_ns['http_json'](big_url, timeout=2, max_bytes=10000)
assert code == 200 and isinstance(body, dict), (code, body)
server.shutdown()
server.server_close()
print('WRITE_HEALTH_RESPONSE_BOUND_OK')

# --- P1-B: single-flight worker; callers get cache or unknown immediately
import concurrent.futures
def settle(predicate, up=True, limit=400):
    last = None
    for _ in range(limit):
        last = ns['collect_write_health'](up)
        if predicate(last):
            return last
        time.sleep(0.01)
    raise AssertionError(f'telemetry never settled: {last}')

collector = ns['collect_write_health']
tasks_calls = []
gate = threading.Event()
def gated(url, timeout, **kwargs):
    if url == 'tasks':
        tasks_calls.append(url)
        gate.wait(3)
        return tasks([row('done')])
    return 200, {'result': {'total_memories': 12}}
ns['_WRITE_HEALTH_STATE'] = {}
ns['http_json'] = gated
t0 = time.monotonic()
busy = collector(True)
assert time.monotonic() - t0 < 0.05, 'caller must not wait on telemetry I/O'
assert busy['counts'] is None and busy['tone'] == 'warn' and busy['telemetry'] == 'busy'
for _ in range(30):
    assert collector(True)['telemetry'] == 'busy'
assert len(tasks_calls) == 1, 'one stuck worker must not spawn replacements'
gate.set()
fresh = settle(lambda h: h['counts'] is not None)
assert fresh['counts']['completed'] == 1 and fresh['telemetry'] == 'idle'
assert fresh['tone'] == 'ok' and fresh['observed_age_s'] is not None
assert len(tasks_calls) == 1
def must_not_fetch(url, timeout, **kwargs):
    raise AssertionError('a fresh cache must not refetch')
ns['http_json'] = must_not_fetch
assert collector(True)['counts']['completed'] == 1
print('WRITE_HEALTH_SINGLE_FLIGHT_OK')

# --- P1-B: stale cache cannot look healthy or resolve an incident, and TTL starts one new scan
ns['http_json'] = lambda url, timeout, **kw: tasks([row('done')]) if url == 'tasks' else (200, {'result': {'total_memories': 12}})
aged = ns['_WRITE_HEALTH_STATE']
aged['tick'] -= 10**6
aged['cache']['mono'] -= 10**6
stale_view = collector(True)
assert stale_view['stale'] is True and stale_view['tone'] == 'warn'
assert stale_view['observed_age_s'] >= 10**6 - 5
settle(lambda h: h['telemetry'] == 'idle' and h['observed_age_s'] < 10**6)
print('WRITE_HEALTH_STALE_OK')

# --- P1-B: stats read is bounded after read+parse as well
ns['_WRITE_HEALTH_STATE'] = {}
ns['_WRITE_HEALTH_STATS_BUDGET_S'] = 0.02
def slow_stats(url, timeout, **kwargs):
    if url == 'tasks':
        return tasks([row('done')])
    time.sleep(0.05)
    return 200, {'result': {'total_memories': 3}}
ns['http_json'] = slow_stats
h = settle(lambda h: h['telemetry'] == 'idle')
assert h['stats_issue'] == 'unavailable' and h['total_memories'] is None
assert h['tone'] == 'warn', 'over-budget stats cannot look healthy'
ns['_WRITE_HEALTH_STATS_BUDGET_S'] = 3.0
print('WRITE_HEALTH_STATS_BUDGET_OK')

# --- P1-B: a crashed telemetry worker leaves unknowns and may be replaced once
ns['_WRITE_HEALTH_STATE'] = {}
attempts = []
def boom(url, timeout, **kwargs):
    attempts.append(url)
    raise RuntimeError('socket-level failure')
ns['http_json'] = boom
assert collector(True)['counts'] is None
h = settle(lambda h: h['telemetry'] == 'idle')
assert h['counts'] is None and h['tone'] == 'warn' and len(attempts) == 1
ns['_WRITE_HEALTH_STATE']['tick'] = time.monotonic() - 10**6
ns['http_json'] = lambda url, timeout, **kw: tasks([row('after-crash')]) if url == 'tasks' else (200, {'result': {'total_memories': 4}})
h = settle(lambda h: h['counts'] is not None)
assert h['counts']['completed'] == 1, 'a crashed worker may be replaced'
print('WRITE_HEALTH_WORKER_FAILURE_OK')

# --- last known good sample, read stamps, and no-longer-observable tasks
ns['_WRITE_HEALTH_STATE'] = {}
ns['http_json'] = lambda url, timeout, **kw: tasks([row('active', 'running')]) if url == 'tasks' else (200, {'result': {'total_memories': 7}})
h = settle(lambda h: h['counts'] is not None)
assert h['tasks_read_success_at'] is not None and h['stats_read_success_at'] is not None
last_good = h['tasks_read_success_at']
ns['_WRITE_HEALTH_STATE']['tick'] = time.monotonic() - 10**6
ns['http_json'] = lambda url, timeout, **kw: (503, {}) if url == 'tasks' else (200, {'result': {'total_memories': 7}})
failed = settle(lambda h: h['counts'] is None and h['telemetry'] == 'idle')
assert failed['tone'] == 'warn'
assert failed['tasks_read_success_at'] == last_good
assert failed['last_known_counts']['completed'] == 0
assert 'lần đọc tốt' in text(failed)
ns['_WRITE_HEALTH_STATE'] = {}
ns['http_json'] = lambda url, timeout, **kw: tasks([row('active', 'running')]) if url == 'tasks' else (200, {'result': {'total_memories': 7}})
settle(lambda h: h['counts'] is not None)
ns['_WRITE_HEALTH_STATE']['tick'] = time.monotonic() - 10**6
ns['http_json'] = lambda url, timeout, **kw: tasks([]) if url == 'tasks' else (200, {'result': {'total_memories': 7}})
vanished = settle(lambda h: h['counts'] is not None and h['telemetry'] == 'idle')
assert vanished['no_longer_observable'] == 1 and vanished['tone'] == 'warn'
assert 'không còn quan sát' in text(vanished)
print('WRITE_HEALTH_RETENTION_OK')

# --- worker started before a restart must never publish into the new epoch
ns['_WRITE_HEALTH_STATE'] = {}
gates = []
def staged(url, timeout, **kwargs):
    if url == 'tasks':
        event = threading.Event()
        gates.append(event)
        event.wait(3)
        return tasks([row('epoch-task')])
    return 200, {'result': {'total_memories': 5}}
ns['http_json'] = staged
collector(True)
while not gates:
    time.sleep(0.01)
ns['invalidate_write_health']()
assert collector(True)['counts'] is None
gates[0].set()
settle(lambda h: len(gates) == 2)
assert ns['_WRITE_HEALTH_STATE'].get('cache') is None, 'pre-restart result must never publish'
gates[1].set()
h = settle(lambda h: h['counts'] is not None)
assert h['counts']['completed'] == 1
print('WRITE_HEALTH_EPOCH_OK')

# --- core snapshot ordering: oldest observation cannot overwrite a newer one
accept = ns['accept_snapshot']
assert accept(0, 1) and accept(3, 4)
assert not accept(4, 4) and not accept(5, 4)
assert accept(7, None), 'foreign snapshots without a token still render'
next_gen = ns['next_snapshot_generation']
ns['_SNAPSHOT_LOCK'] = threading.Lock()
ns['_SNAPSHOT_GEN'] = {'n': 0}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    generations = list(pool.map(lambda _: next_gen(), range(50)))
assert len(set(generations)) == 50 and min(generations) == 1 and max(generations) == 50
collect_node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'collect')
collect_src = ast.get_source_segment(src, collect_node)
assert 'next_snapshot_generation()' in collect_src, 'collect() must tag its observation'
assert '"generation"' in collect_src, 'the published snapshot must carry its generation'
assert 'accept_snapshot(last_gen[0], snap.get("generation"))' in src, 'drain must reject obsolete snapshots'
assert src.count('invalidate_write_health()') >= 2, 'restart paths must invalidate pre-restart telemetry'
print('WRITE_HEALTH_SNAPSHOT_ORDER_OK')

ns['_WRITE_HEALTH_STATE'] = {}
entered, release = threading.Event(), threading.Event()
request_count = []
def held_request(url, timeout, **kwargs):
    if url == 'tasks':
        request_count.append(url)
        entered.set()
        release.wait(3)
        return tasks([row('held')])
    return 200, {'result': {'total_memories': 8}}
ns['http_json'] = held_request
collector(True)
assert entered.wait(1)
for up in (False, True, False, True):
    ns['invalidate_write_health']()
    collector(up)
time.sleep(0.05)
try:
    assert len(request_count) == 1, 'epoch changes must not replace a still-running worker'
finally:
    release.set()
settle(lambda h: h['counts'] is not None)
print('WRITE_HEALTH_RESTART_SINGLE_FLIGHT_OK')

entered.clear()
release.clear()
ns['http_json'] = held_request
assert collector(True)['telemetry'] == 'idle'
ns['_WRITE_HEALTH_STATE']['tick'] -= 10**6
try:
    refreshing = collector(True)
    assert refreshing['telemetry'] == 'busy'
    assert entered.wait(1)
    time.sleep(0.02)
    assert collector(True)['telemetry_busy_s'] is not None
finally:
    release.set()
settle(lambda h: h['telemetry'] == 'idle')
print('WRITE_HEALTH_REFRESH_BUSY_OK')

# --- a stuck worker is visible to the operator without blocking the core snapshot
ns['http_json'] = gated
ns['_WRITE_HEALTH_STATE'] = {}
gate.clear()
collector(True)
for _ in range(200):
    if ns['_WRITE_HEALTH_STATE'].get('inflight') is not None:
        break
    time.sleep(0.005)
assert ns['_WRITE_HEALTH_STATE'].get('inflight') is not None, 'fixture worker never started'
busy_text = text(collector(True))
assert 'Telemetry' in busy_text and 'không chặn' in busy_text, busy_text
gate.set()
settle(lambda h: h['counts'] is not None)
assert 'Telemetry' not in text(collector(True))
print('WRITE_HEALTH_BUSY_TEXT_OK')
