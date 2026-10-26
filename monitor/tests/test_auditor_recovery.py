"""Synthetic auditor regressions. Never contact a provider or write live reports."""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import provider_security_auditor as psa

SCRATCH = Path('C:/Users/rurus/AppData/Local/hermes/cache/scratch/ov-audit-20261025')
FIXTURE = '{"status":"ok","actions":[{"op":"add","target":"memory","content":"test_fact"}]}'
BASE = 'https://example.invalid/Case/v1'
KEY = 'synthetic-credential-123456'


@pytest.fixture(autouse=True)
def isolated():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as folder:
        with patch.object(psa, '__file__', str(Path(folder) / 'auditor.py')), patch('socket.create_connection', side_effect=AssertionError('network forbidden')):
            yield


def response(content=FIXTURE, message=None, finish='stop'):
    return (200, {'choices': [{'message': message if message is not None else {'content': content}, 'finish_reason': finish}]}, '', 100.0)


@pytest.mark.parametrize('content', [
    '{"status":"ok","actions":null}',
    '{"status":"ok","actions":[]}',
    '{"status":"ok","actions":[{"op":"delete"}]}',
    FIXTURE[:-1] + ',"score":NaN}',
    FIXTURE[:-1] + ',"status":"ok"}',
    '\u00a0' + FIXTURE,
    FIXTURE.replace('test_fact', 'other'),
    FIXTURE.replace('"ok"', 'true'),
])
def test_exact_strict_fixture_rejects(content):
    with patch.object(psa, 'execute_bounded_http', return_value=response(content)):
        result = psa.probe_strict_json_vlm_compliance(BASE, KEY, 'synthetic')
    assert result['status'] == 'FAIL'


def complete_results():
    rows = [{'id': name, 'tier': tier, 'status': 'PASS', 'risk_level': 'LOW'}
            for name, tier in psa.PROBE_TIERS.items() if name != 'translation_integrity']
    next(r for r in rows if r['id'] == 'operational_latency')['latency_ms'] = 100.0
    return rows


@pytest.mark.parametrize('mutation,level', [
    ('missing_latency', 2), ('missing_status', 2), ('missing_probe', 2),
    ('warn_t0', 2), ('critical_t1', 1), ('cancelled', 2), ('deadline', 2),
    ('refusal', 3), ('transport_error', 2), ('all_pass', 5),
])
def test_canonical_adapter_missing_and_latched(mutation, level):
    rows = complete_results()
    strict = next(r for r in rows if r['id'] == 'strict_json_vlm')
    if mutation == 'missing_latency':
        rows[-1].pop('latency_ms')
    elif mutation == 'missing_status':
        strict.pop('status')
    elif mutation == 'missing_probe':
        rows.remove(strict)
    elif mutation == 'warn_t0':
        rows[0]['status'] = 'WARN'
    elif mutation == 'critical_t1':
        strict.update(status='FAIL', risk_level='CRITICAL')
    elif mutation == 'cancelled':
        rows.append({'id': 'stopped', 'status': 'STOPPED'})
    elif mutation == 'deadline':
        rows.append({'id': 'deadline', 'status': 'INCONCLUSIVE'})
    elif mutation == 'refusal':
        strict.update(status='REFUSAL', reason_code='ROLE_NOT_SERVED')
    elif mutation == 'transport_error':
        strict.update(status='INCONCLUSIVE', reason_code='TRANSPORT_ERROR')
    latch = psa.core_v31.SecurityLatch()
    decision = psa.evaluate_v31_decision(rows, latch, 0.0, 0.5)
    assert decision.level == level
    if level == 1:
        assert psa.evaluate_v31_decision(complete_results(), latch, 100, 0.5).level == 1


def fake_provider(url, **kwargs):
    body = kwargs['body']
    if b'test_fact' in body:
        return response()
    if b'get_current_time' in body:
        return response(message={'tool_calls': [{'type': 'function', 'function': {
            'name': 'get_current_time', 'arguments': '{"timezone":"Asia/Ho_Chi_Minh"}'}}]})
    if b'BOUNDARY-VERIFICATION' in body:
        return response('---BOUNDARY-VERIFICATION-TOKEN-9281---')
    return response('7')


@pytest.mark.parametrize('status,expected', [('PASS', 5), ('WARN', 2), ('FAIL', 3), ('REFUSAL', 3), ('INCONCLUSIVE', 2)])
def test_audit_projection_is_one_consistent_decision(status, expected):
    row = next(r for r in complete_results() if r['id'] == 'strict_json_vlm')
    row.update(status=status, reason_code='WARN_WRAPPED_JSON' if status == 'WARN' else '')
    if status == 'WARN':
        expected = 3
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider), patch.object(psa, 'probe_strict_json_vlm_compliance', return_value=row):
        verdict = psa.audit_provider(BASE, KEY, 'synthetic')['verdict']
    assert verdict['verdict_level'] == expected
    assert verdict['memory_permitted'] is (expected >= 4)
    assert (verdict['actionable_verdict'] == 'SAFE_TO_ADMIT') is (expected >= 4)
    assert ('VERIFIED' in verdict['role_fitness']['vlm_memory_extractor']) is (expected >= 4)
    assert 'no absolute os safety guarantee' in verdict['disclaimer'].lower()


def test_strict_fixture_pass_disclaims_real_extraction():
    with patch.object(psa, 'execute_bounded_http', return_value=response()):
        result = psa.probe_strict_json_vlm_compliance(BASE, KEY, 'synthetic')
    assert result['status'] == 'PASS'
    assert 'synthetic fixture' in result['summary'].lower()
    assert 'not' in ' '.join(result['findings']).lower()
