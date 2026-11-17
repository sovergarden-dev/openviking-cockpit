"""Quarantine policy: strict digest/identity binding, finite evidence window, manual-only recovery.

Plain script (no pytest dependency): run with
    python -B monitor/tests/test_quarantine_policy.py
Prints one line per scenario and ends with QUARANTINE_POLICY_OK.
"""
import copy
import importlib.util
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('slot_quarantine', root / 'slot_quarantine.py')
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)

KEY = 'sk-dummy-0000-not-a-real-key'
CRED = {'id': 'backup-2', 'provider': 'cl', 'model': 'cl/claude-opus-5-5',
        'api_base': 'https://quota.example.invalid/v1', 'api_key': KEY}
CONF = 'd0' * 32
OTHER = 'c1' * 32
WINDOW = q.EVIDENCE_WINDOW_S


def fail_n(n, cred=CRED, t0=1000.0, conf=CONF, status=401):
    state = q.new_state()
    for i in range(n):
        q.record(state, cred, status, t0 + i, conf_digest=conf)
    return state


def quarantined(cred=CRED, t0=1000.0, conf=CONF, snapshot=None):
    state = fail_n(3, cred, t0, conf)
    q.mark_quarantined(state, cred, t0 + 3, manual=True, conf_digest=conf, snapshot=snapshot)
    return state


def rejects(fn, exc=ValueError):
    try:
        fn()
    except exc:
        return True
    raise AssertionError(f'{fn} did not raise {exc.__name__}')


# 1
def test_identity_is_stable_secret_free_and_index_independent():
    a = q.slot_identity(CRED, 3)
    assert a['digest'] == q.slot_identity(dict(CRED), 9)['digest'], 'identity must not depend on slot index'
    assert KEY not in json.dumps(a), 'identity must not carry the raw api key'
    assert 'api_key' not in a


# 2
def test_identity_changes_with_every_bound_field():
    base = q.slot_identity(CRED)['digest']
    for field, value in (('id', 'other'), ('provider', 'other'), ('model', 'x/y'),
                         ('api_base', 'https://other.invalid/v1'), ('api_key', 'sk-rotated')):
        assert q.slot_identity(dict(CRED, **{field: value}))['digest'] != base, f'{field} change must change identity'


# 3
def test_identity_serialization_cannot_collide():
    d = lambda cred: q.slot_identity(cred)['digest']
    base = {'provider': 'p', 'model': 'c', 'api_base': 'h', 'api_key': ''}
    assert d(dict(base, id='a|b')) != d(dict(base, id='a|b', provider='p|b')), 'delimiter-shaped fields collide'
    assert d(dict(base, id='a|b')) != d(dict(base, id='a', provider='p|b')), 'id/provider boundary collides'
    assert d(dict(base, id=1)) != d(dict(base, id='1')), 'int and str ids must not collide'
    assert d(dict(base, id=None)) != d(dict(base, id='')), 'missing and empty id must differ'
    assert d(dict(base, provider=None)) != d(dict(base, provider='')), 'missing and empty provider must differ'
    rejects(lambda: q.slot_identity(dict(base, id='a', api_key=12345)), ValueError)


# 4
def test_status_classification():
    assert q.classify(200) == 'ok' and q.classify(204) == 'ok'
    assert q.classify(401) == 'auth' and q.classify(403) == 'auth'
    assert q.classify(429) == 'quota' and q.classify(402) == 'quota'
    assert q.classify(502) == 'upstream' and q.classify(503) == 'upstream' and q.classify(None) == 'upstream'
    assert q.classify(400) == 'request' and q.classify(404) == 'request'


# 5
def test_classification_rejects_malformed_status_without_mutation():
    state = fail_n(2)
    before = copy.deepcopy(state)
    for bad in ([], {}, True, False, 401.0, 200.0, '401', object()):
        rejects(lambda b=bad: q.classify(b), ValueError)
        rejects(lambda b=bad: q.record(state, CRED, b, 1005.0, conf_digest=CONF), ValueError)
    assert state == before, 'a malformed status must not mutate state'


# 6
def test_upstream_failures_never_build_evidence():
    state = q.new_state()
    for i, status in enumerate((502, 503, None, 500, 504)):
        q.record(state, CRED, status, 1000.0 + i, conf_digest=CONF)
    rec = q.recommendation(state, CRED, 1010.0, conf_digest=CONF)
    assert rec['action'] == 'none' and rec['failures'] == 0, rec


# 7
def test_three_consecutive_auth_failures_recommend_quarantine():
    assert q.recommendation(fail_n(2), CRED, 1010.0, conf_digest=CONF)['action'] == 'none'
    rec = q.recommendation(fail_n(3), CRED, 1010.0, conf_digest=CONF)
    assert rec['action'] == 'quarantine' and rec['failures'] == 3, rec
    assert KEY not in json.dumps(rec)
    assert 'invalid' not in rec['reason'].lower(), 'auth failure must not claim the key is proven invalid'


# 8
def test_upstream_between_auth_failures_neither_resets_nor_extends():
    state = fail_n(2)
    q.record(state, CRED, 502, 1002.0, conf_digest=CONF)
    assert q.recommendation(state, CRED, 1010.0, conf_digest=CONF)['action'] == 'none', '502 must not count'
    q.record(state, CRED, 401, 1003.0, conf_digest=CONF)
    assert q.recommendation(state, CRED, 1010.0, conf_digest=CONF)['action'] == 'quarantine'


# 9
def test_success_resets_the_failure_streak():
    state = fail_n(2)
    q.record(state, CRED, 200, 1002.0, conf_digest=CONF)
    q.record(state, CRED, 401, 1003.0, conf_digest=CONF)
    rec = q.recommendation(state, CRED, 1010.0, conf_digest=CONF)
    assert rec['action'] == 'none' and rec['failures'] == 1, rec


# 10
def test_conf_digest_is_required_and_exactly_bound_everywhere():
    rejects(lambda: q.record(q.new_state(), CRED, 401, 1000.0), TypeError)
    state = q.new_state()
    before = copy.deepcopy(state)
    for bad in (None, '', '   ', 0, b'd0'):
        rejects(lambda b=bad: q.record(state, CRED, 401, 1000.0, conf_digest=b), ValueError)
    assert state == before, 'blank or non-str digest must not mutate state'
    rejects(lambda: q.recommendation(fail_n(3), CRED, 1010.0), TypeError)
    rejects(lambda: q.recovery_gate(quarantined(), CRED, 1100.0), TypeError)
    rejects(lambda: q.mark_recovered(quarantined(), CRED, 1100.0, manual=True), TypeError)
    rejects(lambda: q.mark_quarantined(fail_n(3), CRED, 1010.0, manual=True), TypeError)
    assert q.recommendation(fail_n(3), CRED, 1010.0, conf_digest=OTHER)['action'] == 'none'
    assert q.recovery_gate(quarantined(), CRED, 1100.0, conf_digest=OTHER)['ready'] is False
    rejects(lambda: q.mark_recovered(quarantined(), CRED, 1100.0, manual=True, conf_digest=OTHER), ValueError)
    # a blank/non-str digest is a caller bug, not a silent "no evidence": every entry point refuses it
    for bad in (None, '', '  ', 0):
        rejects(lambda b=bad: q.recommendation(fail_n(3), CRED, 1010.0, conf_digest=b), ValueError)
        rejects(lambda b=bad: q.recovery_gate(quarantined(), CRED, 1100.0, conf_digest=b), ValueError)
        rejects(lambda b=bad: q.mark_recovered(quarantined(), CRED, 1100.0, manual=True, conf_digest=b),
                ValueError)
        rejects(lambda b=bad: q.mark_quarantined(fail_n(3), CRED, 1011.0, manual=True, conf_digest=b),
                ValueError)


# 11
def test_config_drift_clears_all_evidence():
    state = q.new_state()
    for i in range(2):
        q.record(state, CRED, 401, 1000.0 + i, conf_digest=CONF)
    q.record(state, CRED, 401, 1002.0, conf_digest=OTHER)
    rec = q.recommendation(state, CRED, 1010.0, conf_digest=OTHER)
    assert rec['action'] == 'none' and rec['failures'] == 1, rec
    assert q.recommendation(state, CRED, 1010.0, conf_digest=CONF)['action'] == 'none', \
        'old digest must not inherit new evidence'
    q.record(state, CRED, 401, 1003.0, conf_digest=OTHER)
    q.record(state, CRED, 401, 1004.0, conf_digest=OTHER)
    assert q.recommendation(state, CRED, 1010.0, conf_digest=OTHER)['action'] == 'quarantine'


# 12
def test_failures_outside_the_window_do_not_accumulate():
    assert isinstance(WINDOW, float) and WINDOW == 900.0
    state = q.new_state()
    for i in range(3):
        q.record(state, CRED, 401, 9000.0 + i, conf_digest=CONF)
    assert q.recommendation(state, CRED, 9003.0, conf_digest=CONF)['action'] == 'quarantine'
    assert q.recommendation(state, CRED, 9000.0 + WINDOW, conf_digest=CONF)['action'] == 'quarantine', \
        'evidence exactly one window old still counts (inclusive boundary)'
    stale = q.recommendation(state, CRED, 9002.0 + WINDOW + 1, conf_digest=CONF)
    assert stale['action'] == 'none' and stale['failures'] == 0, stale
    # a fresh failure prunes the aged-out ones instead of stacking on them
    q.record(state, CRED, 401, 20000.0, conf_digest=CONF)
    rec = q.recommendation(state, CRED, 20001.0, conf_digest=CONF)
    assert rec['action'] == 'none' and rec['failures'] == 1, rec


# 13
def test_future_evidence_never_counts():
    state = quarantined()
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    entry = q.state_for(state, CRED)
    entry['successes'] = [1100.0, 1300.0]
    gate = q.recovery_gate(state, CRED, 1200.0, conf_digest=CONF)
    assert gate['ready'] is False, 'a success timestamped after now must not open the gate'
    entry['failure_events'] = [[5000.0, 'auth', 401]]
    assert q.recommendation(state, CRED, 1200.0, conf_digest=CONF)['action'] == 'none'


# 14
def test_mixed_auth_quota_streak_is_not_labelled_exhausted_quota():
    state = q.new_state()
    for i, status in enumerate((401, 429, 402)):
        q.record(state, CRED, status, 1000.0 + i, conf_digest=CONF)
    rec = q.recommendation(state, CRED, 1010.0, conf_digest=CONF)
    assert rec['action'] == 'quarantine', rec
    reason = rec['reason'].lower()
    assert 'mixed' in reason, reason
    assert '401' in reason and '429' in reason, reason
    assert 'exhausted quota' not in reason, reason
    only = q.recommendation(fail_n(3, status=429), CRED, 1010.0, conf_digest=CONF)['reason'].lower()
    assert 'exhausted quota' in only and 'mixed' not in only, only


# 15
def test_quarantine_needs_manual_confirmation_and_stores_no_key():
    state = fail_n(3)
    before = copy.deepcopy(state)
    rejects(lambda: q.mark_quarantined(state, CRED, 1011.0, manual=False, conf_digest=CONF), ValueError)
    rejects(lambda: q.mark_quarantined(state, CRED, 1011.0, manual=None, conf_digest=CONF), ValueError)
    assert state == before, 'a refused quarantine must not mutate state'
    q.mark_quarantined(state, CRED, 1011.0, manual=True, conf_digest=CONF,
                       snapshot='ov.conf-before-slot3-quarantine.json')
    entry = q.state_for(state, CRED)
    assert entry['quarantined'] is True and entry['snapshot'].endswith('.json')
    assert KEY not in json.dumps(state), 'state must never store the key'


# 16
def test_recovery_gate_is_digest_bound_and_rejects_pre_quarantine_evidence():
    state = quarantined()
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    q.record(state, CRED, 200, 1200.0, conf_digest=CONF)
    assert q.recovery_gate(state, CRED, 1300.0, conf_digest=CONF)['ready'] is True
    q.state_for(state, CRED)['successes'] = [900.0, 1200.0]        # before quarantined_at=1003
    assert q.recovery_gate(state, CRED, 1300.0, conf_digest=CONF)['ready'] is False
    q.state_for(state, CRED)['successes'] = [1100.0, 1200.0]
    q.state_for(state, CRED)['config_digest'] = OTHER              # drift away from caller digest
    assert q.recovery_gate(state, CRED, 1300.0, conf_digest=CONF)['ready'] is False


# 17
def test_recovery_needs_two_successes_at_least_60s_apart():
    state = quarantined()
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    assert q.recovery_gate(state, CRED, 1105.0, conf_digest=CONF)['ready'] is False, 'one success is not enough'
    q.record(state, CRED, 200, 1159.0, conf_digest=CONF)
    assert q.recovery_gate(state, CRED, 1160.0, conf_digest=CONF)['ready'] is False, 'gap below 60s must not count'
    q.record(state, CRED, 200, 1219.0, conf_digest=CONF)
    assert q.recovery_gate(state, CRED, 1220.0, conf_digest=CONF)['ready'] is True
    q.record(state, CRED, 200, 1500.0, conf_digest=CONF)
    assert q.recovery_gate(state, CRED, 2500.0, conf_digest=CONF)['ready'] is False, \
        'successes older than the evidence window must expire'


# 18
def test_every_non_success_clears_recovery_successes():
    for status in (502, None, 400, 401, 429):
        state = quarantined()
        q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
        q.record(state, CRED, status, 1300.0, conf_digest=CONF)
        gate = q.recovery_gate(state, CRED, 1310.0, conf_digest=CONF)
        assert gate['ready'] is False and gate['successes'] == 0, (status, gate)
    state = quarantined()
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    q.record(state, CRED, 502, 1300.0, conf_digest=CONF)
    assert len(q.state_for(state, CRED)['failure_events']) == 0, '502 must not become credential evidence'


# 19
def test_identity_change_does_not_inherit_quarantine_or_recovery():
    state = quarantined()
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    q.record(state, CRED, 200, 1200.0, conf_digest=CONF)
    rotated = dict(CRED, api_key='sk-rotated')
    assert q.recovery_gate(state, rotated, 1300.0, conf_digest=CONF)['ready'] is False
    assert q.state_for(state, rotated)['quarantined'] is False
    assert q.recommendation(state, rotated, 1300.0, conf_digest=CONF)['action'] == 'none'


# 20
def test_elapsed_time_alone_never_restores_and_recovery_stays_manual():
    state = quarantined()
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    q.record(state, CRED, 200, 1200.0, conf_digest=CONF)
    assert q.recovery_gate(state, CRED, 99999.0, conf_digest=CONF)['ready'] is False, 'stale successes must expire'
    q.record(state, CRED, 200, 99900.0, conf_digest=CONF)
    q.record(state, CRED, 200, 99990.0, conf_digest=CONF)
    assert q.recovery_gate(state, CRED, 99995.0, conf_digest=CONF)['ready'] is True
    assert q.state_for(state, CRED)['quarantined'] is True, 'the gate alone must not unquarantine'
    before = copy.deepcopy(state)
    rejects(lambda: q.mark_recovered(state, CRED, 99999.0, manual=False, conf_digest=CONF), ValueError)
    assert state == before, 'a refused recovery must not mutate state'
    q.mark_recovered(state, CRED, 99999.0, manual=True, conf_digest=CONF)
    assert q.state_for(state, CRED)['quarantined'] is False
    assert q.recovery_gate(state, CRED, 99999.0, conf_digest=CONF)['ready'] is False, \
        'recovery must not be re-applied'


# 21
def test_record_rejects_nonchronological_time_before_mutating():
    state = fail_n(3)                       # failures at 1000..1002
    q.mark_quarantined(state, CRED, 1003.0, manual=True, conf_digest=CONF)
    before = copy.deepcopy(state)
    rejects(lambda: q.record(state, CRED, 200, 1002.5, conf_digest=CONF), ValueError)
    rejects(lambda: q.record(state, CRED, 401, 500.0, conf_digest=CONF), ValueError)
    assert state == before, 'time older than quarantine must be refused without mutating state'
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    before = copy.deepcopy(state)
    rejects(lambda: q.record(state, CRED, 200, 1099.0, conf_digest=CONF), ValueError)
    rejects(lambda: q.record(state, CRED, 401, 1000.0, conf_digest=CONF), ValueError)
    assert state == before, 'time older than the last evidence must be refused'


# 22
def test_malformed_timestamps_are_rejected_without_mutation():
    state = fail_n(3)
    before = copy.deepcopy(state)
    for bad in (float('nan'), float('inf'), float('-inf'), -1.0, '1010', None, True, [1010.0]):
        rejects(lambda b=bad: q.record(state, CRED, 200, b, conf_digest=CONF), ValueError)
        rejects(lambda b=bad: q.mark_quarantined(state, CRED, b, manual=True, conf_digest=CONF), ValueError)
    assert state == before, 'malformed time must not mutate state'
    state = quarantined()
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    q.record(state, CRED, 200, 1200.0, conf_digest=CONF)
    before = copy.deepcopy(state)
    for bad in (float('nan'), float('inf'), -1, '1300', None):
        rejects(lambda b=bad: q.mark_recovered(state, CRED, b, manual=True, conf_digest=CONF), ValueError)
    assert state == before
    assert q.state_for(state, CRED)['quarantined'] is True


# 23
def test_malformed_stored_evidence_fails_closed():
    state = quarantined()
    for bad in ([], {}, 'nope', [1100.0, '1200'], [1100.0, None], [float('nan'), 1200.0],
                [1200.0, 1100.0], [1100.0], [1100.0, 1200.0, 1300.0]):
        q.state_for(state, CRED)['successes'] = copy.deepcopy(bad)
        assert q.recovery_gate(state, CRED, 1400.0, conf_digest=CONF)['ready'] is False, bad
    q.state_for(state, CRED)['successes'] = [1100.0, 1200.0]
    for bad in (None, 3, [[1000.0]], [[1000.0, 'auth']], [['1000', 'auth', 401]],
                [[1000.0, 'bogus', 401]], [[1000.0, 'auth', True]], [[1000.0, 'quota', 429.0]]):
        q.state_for(state, CRED)['failure_events'] = copy.deepcopy(bad)
        assert q.recommendation(state, CRED, 1400.0, conf_digest=CONF)['action'] == 'none', bad
    q.state_for(state, CRED)['failure_events'] = [[1000.0, 'auth', 401]] * 3
    assert q.recommendation(state, CRED, 1400.0, conf_digest=CONF)['action'] == 'none', \
        'duplicate timestamps are not three separate probes'


# 24
def test_module_has_no_io_probe_or_scheduler_surface():
    names = {n for n in dir(q) if not n.startswith('_')}
    assert not {'probe', 'schedule', 'thread', 'write_conf', 'apply_conf_edit', 'open', 'save', 'load'} & names, names
    assert not any(n.startswith(('probe_', 'auto_')) for n in names), names


# 25
def test_no_key_derived_identifier_is_ever_echoed():
    key_ref = q.slot_identity(CRED)['key_ref']
    ident_digest = q.slot_identity(CRED)['digest']
    state = fail_n(3)
    q.mark_quarantined(state, CRED, 1011.0, manual=True, conf_digest=CONF)
    q.record(state, CRED, 200, 1100.0, conf_digest=CONF)
    q.record(state, CRED, 200, 1200.0, conf_digest=CONF)
    one_success = quarantined()
    q.record(one_success, CRED, 200, 1100.0, conf_digest=CONF)
    verdicts = [q.recommendation(state, CRED, 1300.0, conf_digest=CONF),          # already quarantined
                q.recommendation(fail_n(3), CRED, 1010.0, conf_digest=CONF),      # quarantine advice
                q.recovery_gate(state, CRED, 1300.0, conf_digest=CONF),           # ready
                q.recovery_gate(one_success, CRED, 1200.0, conf_digest=CONF)]     # not ready
    for out in verdicts:
        text = json.dumps(out)
        assert KEY not in text, text
        for derived in (key_ref, ident_digest, CONF):
            assert derived not in text, f'verdict echoes a derived identifier: {text}'
    assert KEY not in json.dumps(state), 'state must never store the raw key'


def main():
    tests = [(n, o) for n, o in list(globals().items()) if n.startswith('test_') and callable(o)]
    for name, fn in tests:
        fn()
        print('ok', name)
    print(f'{len(tests)} scenarios OK')
    print('QUARANTINE_POLICY_OK')


if __name__ == '__main__':
    main()
