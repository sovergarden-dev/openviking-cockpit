"""Quarantine policy for ov.conf VLM slots.

Pure stdlib state machine: no probing, no scheduling, no file writes, no
persistence. Callers feed probe outcomes and ask for a verdict; the ov.conf
mutation stays in ``apply_conf_edit`` and quarantine/restore stay manual clicks.

Evidence binds to a canonical slot identity (id + provider + model + api_base +
key reference) *and* to an explicit ``conf_digest`` of the config it came from.
The key reference is a truncated SHA-256 of the api_key: a derived identifier,
not the secret, and not a keyed MAC — it is never echoed in verdicts or logs.
Timestamps must be finite epoch seconds recorded in chronological order, and
failure/success evidence older than ``EVIDENCE_WINDOW_S`` stops counting.
"""
from __future__ import annotations

import hashlib
import json
import math

FAILURES_REQUIRED = 3
RECOVERY_SUCCESSES = 2
RECOVERY_MIN_GAP_S = 60.0
EVIDENCE_WINDOW_S = 900.0

AUTH = frozenset({401, 403})
QUOTA = frozenset({402, 429})
KINDS = ('auth', 'quota')


def _timestamp(value, label: str = 'probe time') -> float:
    """Finite, nonnegative epoch seconds, or ValueError. NaN/inf would forge evidence."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value < 0:
        raise ValueError(f'{label} must be finite nonnegative epoch seconds, got {type(value).__name__}')
    return float(value)


def _conf_digest(value) -> str:
    """Explicit nonblank config digest, compared verbatim."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError('conf_digest must be a nonblank config digest string')
    return value


def classify(status) -> str:
    """Probe verdict class. Upstream faults say nothing about the credential.

    Only ``int`` or ``None`` are accepted: a float, bool, str, list or dict status
    is a caller bug, and guessing a class from it would forge evidence.
    """
    if status is None:
        return 'upstream'
    if isinstance(status, bool) or not isinstance(status, int):
        raise ValueError(f'probe status must be an int or None, got {type(status).__name__}')
    if 200 <= status < 300:
        return 'ok'
    if status in AUTH:
        return 'auth'
    if status in QUOTA:
        return 'quota'
    if status >= 500:
        return 'upstream'
    return 'request'


def new_state() -> dict:
    return {'version': 2, 'slots': {}}


def _blank_entry() -> dict:
    return {'id': None, 'provider': None, 'model': None, 'host': None, 'key_ref': None,
            'config_digest': None, 'failure_events': [], 'successes': [],
            'quarantined': False, 'snapshot': None}


def slot_identity(cred: dict, index: int | None = None) -> dict:
    """Secret-free identity of one credential entry."""
    key = cred.get('api_key') or ''
    if not isinstance(key, str):
        raise ValueError('api_key must be a string')
    key_ref = hashlib.sha256(key.encode('utf-8')).hexdigest()[:12] if key else 'none'
    ident = {
        'index': index,
        'id': cred.get('id'),
        'provider': cred.get('provider'),
        'model': cred.get('model'),
        'host': cred.get('api_base'),
        'key_ref': key_ref,
    }
    # Canonical JSON serialization keeps types apart so 'a|b'+'c' can never hash like 'a'+'b|c'.
    payload = json.dumps([ident['id'], ident['provider'], ident['model'], ident['host'], ident['key_ref']],
                         separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    ident['digest'] = hashlib.sha256(payload.encode('utf-8')).hexdigest()[:32]
    return ident


def _ensure(state: dict, ident: dict) -> dict:
    entry = state['slots'].setdefault(ident['digest'], _blank_entry())
    entry.update(id=ident['id'], provider=ident['provider'], model=ident['model'],
                 host=ident['host'], key_ref=ident['key_ref'])
    return entry


def state_for(state: dict, cred: dict) -> dict:
    return state['slots'].get(slot_identity(cred)['digest']) or _blank_entry()


def _finite(value) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def _last_evidence_time(entry: dict) -> float | None:
    """Newest timestamp already recorded for this entry, so probes stay chronological."""
    times = []
    events = entry.get('failure_events')
    if isinstance(events, list):
        times.extend(float(ev[0]) for ev in events if isinstance(ev, list) and ev and _finite(ev[0]))
    ok = entry.get('successes')
    if isinstance(ok, list):
        times.extend(float(t) for t in ok if _finite(t))
    quarantined_at = entry.get('quarantined_at')
    if _finite(quarantined_at):
        times.append(float(quarantined_at))
    return max(times) if times else None


def _prune(events, now: float) -> list:
    """Drop malformed and aged-out events; only in-window ones accumulate."""
    if not isinstance(events, list):
        return []
    return [ev for ev in events
            if isinstance(ev, list) and len(ev) == 3 and _finite(ev[0])
            and now - EVIDENCE_WINDOW_S <= ev[0] <= now]


def _live_events(events, now: float) -> list | None:
    """In-window well-formed failure evidence, or None if the stored evidence is untrustworthy."""
    if not isinstance(events, list):
        return None
    live, seen = [], set()
    for ev in events:
        if not isinstance(ev, list) or len(ev) != 3:
            return None
        t, kind, status = ev
        try:
            t = _timestamp(t, 'failure time')
            if kind not in KINDS or classify(status) != kind:
                return None
        except ValueError:
            return None
        if t > now or t in seen:
            return None
        if t < now - EVIDENCE_WINDOW_S:
            continue
        seen.add(t)
        live.append((t, kind, status))
    return live


def record(state: dict, cred: dict, status, now: float, *, conf_digest: str) -> dict:
    """Record one probe outcome for this exact identity.

    Validates time, config digest and status class *before* touching state. Evidence
    is bound to ``conf_digest``: a different digest starts a fresh streak, and the
    caller must supply it explicitly — there is no unbound mode.
    """
    now = _timestamp(now)
    digest = _conf_digest(conf_digest)
    kind = classify(status)
    ident = slot_identity(cred)
    prior = state['slots'].get(ident['digest'])
    if prior is not None:
        last = _last_evidence_time(prior)
        if last is not None and now < last:
            raise ValueError(f'probe time {now} is older than the newest recorded evidence {last}')
    entry = _ensure(state, ident)
    if entry['config_digest'] != digest:
        entry['config_digest'] = digest
        entry['failure_events'] = []
        entry['successes'] = []
    if kind == 'ok':
        entry['failure_events'] = []
        entry['successes'] = (entry['successes'] + [now])[-RECOVERY_SUCCESSES:]
    elif kind in KINDS:
        entry['failure_events'] = _prune(entry['failure_events'], now) + [[now, kind, status]]
        entry['successes'] = []          # any credential verdict clears recovery evidence
        entry['last_status'] = status
    else:
        # upstream/request: no credit and no reset of the failure streak, but not a success either.
        entry['successes'] = []
    return entry


def recommendation(state: dict, cred: dict, now: float, *, conf_digest: str) -> dict:
    """Advise quarantining a slot. Advisory only: nothing is mutated.

    Requires the explicit ``conf_digest`` the evidence was recorded under and only
    counts failures inside ``EVIDENCE_WINDOW_S``; unknown digests, future-dated or
    malformed evidence never justify a quarantine.
    """
    now = _timestamp(now, 'recommendation time')
    digest = _conf_digest(conf_digest)
    ident = slot_identity(cred)
    entry = state['slots'].get(ident['digest'])
    if not entry:
        return {'action': 'none', 'failures': 0, 'reason': 'no evidence for this identity'}
    raw = entry.get('failure_events')
    if entry.get('quarantined'):
        return {'action': 'none', 'failures': len(raw) if isinstance(raw, list) else 0,
                'reason': 'already quarantined'}
    if entry.get('config_digest') != digest:
        return {'action': 'none', 'failures': 0, 'reason': 'config digest does not match recorded evidence'}
    events = _live_events(raw, now)
    if events is None:
        return {'action': 'none', 'failures': 0, 'reason': 'malformed or future-dated failure evidence'}
    failures = len(events)
    if failures < FAILURES_REQUIRED:
        return {'action': 'none', 'failures': failures,
                'reason': f'{failures}/{FAILURES_REQUIRED} failures within {int(EVIDENCE_WINDOW_S)}s'}
    kinds = {kind for _, kind, _ in events}
    statuses = ', '.join(str(s) for s in sorted({s for _, _, s in events}))
    if kinds == {'auth'}:
        why = f'slot rejected with HTTP {statuses}; key validity unproven, the model route does not work'
    elif kinds == {'quota'}:
        why = f'slot exhausted quota with HTTP {statuses}'
    else:
        why = (f'mixed auth/quota streak (HTTP {statuses}); rate limiting and rejections both present, '
               'key validity unproven')
    return {'action': 'quarantine', 'failures': failures, 'reason': why,
            'identity': {'id': ident['id'], 'provider': ident['provider'],
                         'model': ident['model'], 'host': ident['host']}}


def recovery_gate(state: dict, cred: dict, now: float, *, conf_digest: str) -> dict:
    """Ready to re-admit only with 2 in-window successes >= 60s apart, after quarantine."""
    now = _timestamp(now, 'recovery gate time')
    digest = _conf_digest(conf_digest)
    entry = state['slots'].get(slot_identity(cred)['digest'])
    if not entry or not entry.get('quarantined'):
        return {'ready': False, 'successes': 0, 'reason': 'not quarantined'}
    if entry.get('config_digest') != digest:
        return {'ready': False, 'successes': 0, 'reason': 'config digest does not match recorded evidence'}
    raw = entry.get('successes')
    if not isinstance(raw, list) or len(raw) > RECOVERY_SUCCESSES:
        return {'ready': False, 'successes': 0, 'reason': 'malformed recovery evidence'}
    try:
        quarantined_at = _timestamp(entry.get('quarantined_at'), 'quarantine time')
        times = [_timestamp(t, 'recovery success time') for t in raw]
    except ValueError:
        return {'ready': False, 'successes': len(raw), 'reason': 'malformed recovery evidence'}
    if any(t > now for t in times):
        return {'ready': False, 'successes': len(times), 'reason': 'recovery evidence is in the future'}
    if any(t < quarantined_at for t in times):
        return {'ready': False, 'successes': len(times), 'reason': 'recovery evidence predates quarantine'}
    times = [t for t in times if t >= now - EVIDENCE_WINDOW_S]
    if len(times) < RECOVERY_SUCCESSES:
        return {'ready': False, 'successes': len(times),
                'reason': f'{len(times)}/{RECOVERY_SUCCESSES} recovery probes passed inside '
                          f'{int(EVIDENCE_WINDOW_S)}s'}
    if any(later <= earlier for earlier, later in zip(times, times[1:])):
        return {'ready': False, 'successes': len(times), 'reason': 'recovery evidence out of order'}
    if times[-1] - times[-2] < RECOVERY_MIN_GAP_S:
        return {'ready': False, 'successes': len(times),
                'reason': f'probes closer than {int(RECOVERY_MIN_GAP_S)}s'}
    return {'ready': True, 'successes': len(times), 'reason': 'manual apply required'}


def mark_quarantined(state: dict, cred: dict, now: float, *, manual: bool,
                     conf_digest: str, snapshot: str | None = None) -> dict:
    """Close the gate. Requires the manual click; never triggered by a timer."""
    if manual is not True:
        raise ValueError('Quarantine requires explicit manual confirmation')
    now = _timestamp(now, 'quarantine time')
    digest = _conf_digest(conf_digest)
    ident = slot_identity(cred)
    prior = state['slots'].get(ident['digest'])
    if prior is not None:
        last = _last_evidence_time(prior)
        if last is not None and now < last:
            raise ValueError(f'quarantine time {now} is older than the newest recorded evidence {last}')
    entry = _ensure(state, ident)
    if entry['config_digest'] != digest:
        entry['config_digest'] = digest
        entry['failure_events'] = []
        entry['successes'] = []
    entry.update(quarantined=True, quarantined_at=now, successes=[], snapshot=snapshot)
    return entry


def mark_recovered(state: dict, cred: dict, now: float, *, manual: bool, conf_digest: str) -> dict:
    """Re-admit. Requires the manual click and a satisfied, digest-bound recovery gate."""
    if manual is not True:
        raise ValueError('Recovery requires explicit manual apply')
    now = _timestamp(now, 'recovery time')
    digest = _conf_digest(conf_digest)
    gate = recovery_gate(state, cred, now, conf_digest=digest)
    if not gate['ready']:
        raise ValueError(f"Recovery gate not satisfied: {gate['reason']}")
    entry = state['slots'][slot_identity(cred)['digest']]
    entry.update(quarantined=False, recovered_at=now, failure_events=[], successes=[])
    return entry
