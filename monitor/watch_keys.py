"""Bounded, independent watch credentials. No runtime configuration writes."""
import copy
import ipaddress
import math
import time
import threading
import uuid
from urllib.parse import urlsplit

MAX_WATCHES = 7


def validate_watch_records(items):
    if not isinstance(items, list) or len(items) > MAX_WATCHES:
        raise ValueError('Danh sách THEO DÕI không hợp lệ')
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('Bản ghi THEO DÕI không hợp lệ')
        identifier = item.get('id')
        if not isinstance(identifier, str) or not identifier or identifier in seen:
            raise ValueError('ID theo dõi không hợp lệ hoặc trùng lặp')
        seen.add(identifier)
        for field in ('alias', 'model', 'api_base', 'api_key', 'auto_disabled_reason'):
            if field in item and not isinstance(item[field], str):
                raise ValueError('Trường THEO DÕI không hợp lệ')
        for field in ('rev', 'fail_streak', 'auth_fail_streak'):
            value = item.get(field, 0)
            if type(value) is not int or value < 0:
                raise ValueError('Phiên bản THEO DÕI không hợp lệ')
        probe = item.get('last_probe')
        if probe is not None and not isinstance(probe, dict):
            raise ValueError('Kết quả THEO DÕI không hợp lệ')
        for value in (item.get('next_probe_at', 0), item.get('cooldown_until', 0),
                      (probe or {}).get('at', 0)):
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError('Thời điểm THEO DÕI không hợp lệ')
        if probe and probe.get('at'):
            try:
                time.localtime(probe['at'])
            except (ValueError, OverflowError, OSError) as exc:
                raise ValueError('Thời điểm THEO DÕI không hợp lệ') from exc


class WatchBatch:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.run_id = 0
        self.revisions = {}
        self.auto_ids = set()
        self.thread = None
        self.pending_run = None

    @property
    def busy(self):
        return self.pending_run is not None or (self.thread is not None and self.thread.is_alive())

    def complete(self, run_id):
        with self.lock:
            if self.pending_run == run_id:
                self.pending_run = None

    def sync(self, items):
        with self.lock:
            self.revisions = {item['id']: item.get('rev', 0) for item in items}
            self.auto_ids = {item['id'] for item in items if item.get('auto_enabled')}

    def cancel(self):
        with self.lock:
            self.run_id += 1
            self.stop.set()
            self.pending_run = None

    def accepts(self, run_id, watch_id, rev):
        with self.lock:
            return (run_id == self.run_id and not self.stop.is_set()
                    and self.revisions.get(watch_id) == rev)

    def start(self, items, probe, emit, *, auto=False):
        with self.lock:
            if self.busy:
                return False
            snapshot = copy.deepcopy([item for item in items
                                      if item.get('api_key') and not item.get('_dpapi_locked')])
            if not snapshot:
                return False
            self.run_id += 1
            run_id = self.run_id
            self.pending_run = run_id
            self.stop.clear()

            def work():
                try:
                    for item in snapshot:
                        if not self.accepts(run_id, item['id'], item.get('rev', 0)):
                            continue
                        with self.lock:
                            enabled = item['id'] in self.auto_ids
                        if auto and not enabled:
                            continue
                        try:
                            result = probe(item['model'], item['api_base'], item['api_key'],
                                           timeout=20.0, max_tokens=64)
                        except Exception:
                            result = {'ok': False, 'category': 'network', 'ms': None}
                        emit(('watch_result', run_id, item['id'], item.get('rev', 0), result))
                finally:
                    emit(('watch_done', run_id))

            self.thread = threading.Thread(target=work, daemon=True, name='ov-watch-probe')
            self.thread.start()
            return True


def upsert_watch(items, incoming):
    identifier = incoming.get('id')
    old = next((item for item in items if item.get('id') == identifier), None) if identifier else None
    if identifier and old is None:
        raise ValueError('Key theo dõi không còn tồn tại')
    if old is None and len(items) >= MAX_WATCHES:
        raise ValueError('Tối đa 7 key theo dõi')
    record = copy.deepcopy(old or {})
    for name in ('alias', 'model', 'api_base', 'api_key'):
        value = incoming.get(name, record.get(name, ''))
        if not isinstance(value, str) or len(value) > (8192 if name == 'api_key' else 2048):
            raise ValueError('Trường theo dõi không hợp lệ')
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Trường theo dõi chứa ký tự điều khiển')
        record[name] = value.strip()
    if record['api_key'].startswith('dpapi:'):
        raise ValueError('Không nhập trực tiếp chuỗi dpapi:; hãy nhập API key hoặc ${BIẾN_MÔI_TRƯỜNG}')
    if not record['model']:
        raise ValueError('Thiếu model dùng để thử')
    try:
        parsed = urlsplit(record['api_base'])
        parsed.port
        host = parsed.hostname or ''
        local = host.lower() == 'localhost'
        if not local:
            try:
                local = ipaddress.ip_address(host).is_loopback
            except ValueError:
                local = False
        if (not host or parsed.scheme not in ('http', 'https') or parsed.username or parsed.password
                or parsed.query or parsed.fragment or any(ord(c) < 33 for c in record['api_base'])):
            raise ValueError('Base URL không hợp lệ; không dùng credential/query trong URL')
        if parsed.scheme == 'http' and not local:
            raise ValueError('Endpoint ngoài máy phải dùng HTTPS')
        if not parsed.path.rstrip('/').endswith('/v1'):
            raise ValueError('Base URL phải kết thúc bằng /v1')
    except (ValueError, TypeError) as exc:
        raise ValueError(str(exc) or 'Base URL không hợp lệ') from exc
    record['api_base'] = record['api_base'].rstrip('/')
    locked = bool(old and old.get('_dpapi_locked') and not record['api_key'] and old.get('_enc'))
    if not record['api_key'] and not locked:
        raise ValueError('Thiếu API key; không tự lấy key theo Base URL')

    changed = old is None or any(record.get(k) != old.get(k) for k in ('model', 'api_base', 'api_key'))
    if changed and not locked:
        for name in ('_enc', '_sha', '_dpapi_locked'):
            record.pop(name, None)
    record['id'] = identifier or 'watch-' + uuid.uuid4().hex
    record['rev'] = int((old or {}).get('rev', 0)) + 1
    record['auto_enabled'] = bool(incoming.get('auto_enabled', old.get('auto_enabled', False))) if old else False
    if changed or (record['auto_enabled'] and not old.get('auto_enabled')):
        record.update(fail_streak=0, auth_fail_streak=0, cooldown_until=0, next_probe_at=0, auto_disabled_reason='')
    if changed:
        record.pop('last_probe', None)
    return [record if old and item.get('id') == identifier else copy.deepcopy(item) for item in items] + ([] if old else [record])


def watch_due(record, now=None):
    now = time.time() if now is None else now
    return bool(record.get('auto_enabled') and record.get('api_key') and not record.get('_dpapi_locked')
                and now >= max(record.get('cooldown_until') or 0, record.get('next_probe_at') or 0))


def apply_watch_result(record, result, *, now=None, interval=600):
    now = time.time() if now is None else now
    updated = copy.deepcopy(record)
    ok = result.get('ok') is True
    code = result.get('http_code')
    category = result.get('category') or ('ok' if ok else 'invalid-response')
    allowed = {'ok', 'network', 'timeout', 'rate-limit', 'upstream', 'auth-or-quota',
               'model-not-found', 'bad-request', 'http', 'secret-unresolved', 'invalid-response'}
    if category not in allowed:
        category = 'invalid-response'
    text = 'OK' if ok else (f'HTTP {code} · {category}' if type(code) is int else category)
    ms = result.get('ms')
    updated['last_probe'] = {'ok': ok, 'text': text, 'http_code': code if type(code) is int else None,
                             'category': category, 'ms': ms if type(ms) in (int, float) else None, 'at': now}
    streak = 0 if ok else min(100, int(updated.get('fail_streak') or 0) + 1)
    auth_streak = int(updated.get('auth_fail_streak') or 0) + 1 if code in (401, 403) else 0
    cooldown = 0 if ok else min(3600, 60 * 2 ** min(streak - 1, 6))
    if code == 402 or code == 404 or category == 'bad-request':
        cooldown = max(cooldown, 1800)
    updated.update(fail_streak=streak, auth_fail_streak=auth_streak,
                   cooldown_until=now + cooldown if cooldown else 0,
                   next_probe_at=now + max(60, interval, cooldown))
    if auth_streak >= 2:
        updated.update(auto_enabled=False, auto_disabled_reason='Tự tắt Auto: HTTP 401/403 liên tiếp')
    if ok:
        updated['auto_disabled_reason'] = ''
    return updated
