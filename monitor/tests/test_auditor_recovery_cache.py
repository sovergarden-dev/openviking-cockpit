"""Scoped cache and publication regressions; synthetic data only."""
import copy
import json
import os
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from test_auditor_recovery import psa, isolated, BASE, KEY, fake_provider, complete_results


def audit(**kwargs):
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider):
        return psa.audit_provider(BASE, KEY, 'synthetic', **kwargs)


def read(**kwargs):
    return psa.get_latest_audit_report(BASE, 'synthetic', api_key=KEY, **kwargs)


def test_cache_requires_explicit_correct_credential_and_case_exact_scope():
    report = audit()
    assert read()['verdict']['memory_permitted'] is True
    assert psa.get_latest_audit_report(BASE, 'synthetic') is None
    assert psa.get_latest_audit_report(BASE, 'synthetic', api_key='other') is None
    assert psa.get_latest_audit_report(BASE.lower(), 'synthetic', api_key=KEY) is None
    assert psa.get_latest_audit_report(BASE, 'Synthetic', api_key=KEY) is None
    assert psa.get_latest_audit_report(BASE.replace('example.invalid', 'EXAMPLE.INVALID')+'/', 'synthetic', api_key=KEY)
    assert Path(report['saved_report_file']).exists()


@pytest.mark.parametrize('age,ttl,valid', [(0,10,True),(9,10,True),(10,10,False),(11,10,False),(-1,10,False),(0,0,False)])
def test_explicit_epoch_half_open_ttl_not_mtime(age, ttl, valid):
    with patch.object(psa.time, 'time', return_value=1000000):
        report = audit()
    os.utime(report['saved_report_file'], (500,500))
    with patch.object(psa.time, 'time', return_value=1000000+age):
        assert (read(max_age_s=ttl) is not None) is valid


@pytest.mark.parametrize('ttl', [True,-1,float('nan'),float('inf'),'10',None])
def test_invalid_ttl_is_untrusted(ttl):
    audit()
    assert read(max_age_s=ttl) is None


@pytest.mark.parametrize('mutation', ['version','policy','probe','scope','epoch','missing','projection','bool','duplicate','legacy','results'])
def test_malformed_stale_or_inconsistent_report_is_untrusted(mutation):
    report = audit()
    path = Path(report['saved_report_file'])
    data = json.loads(path.read_text(encoding='utf-8'))
    if mutation == 'version':
        data['verdict']['classifier_version'] = '2.2.0'
    elif mutation in ('policy','probe'):
        data['cache_scope'][mutation+'_version'] = 'old'
    elif mutation == 'scope':
        data['cache_scope']['credential_digest'] = '0'*64
    elif mutation == 'epoch':
        data['epoch_ts'] = 'yesterday'
    elif mutation == 'missing':
        data.pop('epoch_ts')
    elif mutation == 'projection':
        data['verdict']['actionable_verdict'] = 'BLOCKED_SECURITY'
    elif mutation == 'bool':
        data['verdict']['memory_permitted'] = 1
    elif mutation == 'legacy':
        data.pop('cache_scope')
    elif mutation == 'results':
        data['results'] = []
    raw = json.dumps(data)
    if mutation == 'duplicate':
        raw = raw[:-1]+',"epoch_ts":0}'
    path.write_text(raw, encoding='utf-8')
    assert read() is None


def test_report_recursively_redacts_exact_key_and_controls():
    row = next(r for r in complete_results() if r['id']=='operational_latency')
    row.update(summary=KEY+'\x1b[2J\u202e', findings=[{KEY:[KEY, 'Bearer other-token']}], evidence='prefix '+KEY+' suffix')
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider), patch.object(psa, 'probe_reasoning_and_latency_metrics', return_value=row):
        report = psa.audit_provider(BASE, KEY, 'synthetic')
    for text in (json.dumps(report), Path(report['saved_report_file']).read_text(encoding='utf-8'), json.dumps(read())):
        assert KEY not in text
        assert '\\u001b' not in text
        assert '\\u202e' not in text
        assert 'other-token' not in text
    assert '[REDACTED]' in json.dumps(report)


def test_atomic_fsync_replace_and_no_temp_leftovers():
    with patch.object(psa.os, 'fsync', wraps=os.fsync) as sync, patch.object(psa.os, 'replace', wraps=os.replace) as replace:
        report = audit()
    assert sync.called and replace.called
    assert Path(replace.call_args.args[0]).parent == Path(report['saved_report_file']).parent
    assert not list(Path(report['saved_report_file']).parent.glob('*.tmp'))


def test_failed_critical_save_cannot_resurrect_earlier_pass():
    first = audit()
    assert read()
    row = dict(id='ansi_control_hygiene', tier=0, status='CRITICAL_FAIL', risk_level='CRITICAL')
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider), patch.object(psa, 'probe_ansi_and_control_injection', return_value=row), patch.object(psa.os, 'replace', side_effect=OSError('synthetic save failure')):
        failed = psa.audit_provider(BASE, KEY, 'synthetic')
    assert failed['saved_report_file'] is None
    assert failed['verdict']['verdict_level'] == 1
    assert read() is None
    assert not list(Path(first['saved_report_file']).parent.glob('*.tmp'))
    audit()
    assert read()


def test_cancel_during_fsync_reprojects_before_atomic_publication():
    stop = threading.Event()
    original = os.fsync
    def sync(fd):
        original(fd)
        stop.set()
    with patch.object(psa.os, 'fsync', side_effect=sync):
        report = audit(stop_event=stop)
    assert not report['verdict']['memory_permitted']
    assert not read()['verdict']['memory_permitted']
