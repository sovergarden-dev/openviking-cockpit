import threading
from unittest.mock import patch
import pytest
from test_auditor_recovery import psa, isolated, BASE, KEY, response, fake_provider, complete_results


def test_cancel_before_baseline_sends_no_requests():
    stop = threading.Event()
    stop.set()
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider) as http:
        report = psa.audit_provider(BASE, KEY, 'synthetic', stop_event=stop)
    assert http.call_count == 0
    assert report['verdict']['memory_permitted'] is False


@pytest.mark.parametrize('probe', ['probe_ansi_and_control_injection', 'probe_strict_json_vlm_compliance'])
def test_confirmed_violation_stops_remaining_requests(probe):
    row = {'id':'strict_json_vlm' if 'strict' in probe else 'ansi_control_hygiene',
           'tier':1 if 'strict' in probe else 0, 'status':'FAIL', 'risk_level':'CRITICAL'}
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider) as http, patch.object(psa, probe, return_value=row):
        report = psa.audit_provider(BASE, KEY, 'synthetic')
    assert report['verdict']['verdict_level'] == 1
    assert report['results'][-1]['risk_level'] == 'CRITICAL'
    assert http.call_count == (4 if 'strict' in probe else 1)


def test_cancel_between_canary_steps():
    stop = threading.Event()
    calls = []
    def transport(url, **kwargs):
        calls.append(kwargs)
        stop.set()
        return response('ack')
    with patch.object(psa, 'execute_bounded_http', side_effect=transport):
        result = psa.probe_canary_session_isolation(BASE, KEY, 'synthetic', stop_event=stop)
    assert len(calls) == 1
    assert result['status'] == 'INCONCLUSIVE'


def test_retry_ladder_shares_one_wall_budget():
    clock = [0.0]
    calls = []
    def transport(url, **kwargs):
        calls.append(kwargs['timeout'])
        clock[0] += 2
        return response('', finish='length')
    with patch.object(psa.time, 'monotonic', side_effect=lambda:clock[0]), patch.object(psa, 'execute_bounded_http', side_effect=transport):
        result = psa.probe_strict_json_vlm_compliance(BASE, KEY, 'synthetic', timeout=3)
    assert len(calls) == 2
    assert calls == [3,1]
    assert result['status'] == 'INCONCLUSIVE'


def test_final_probe_cancel_cannot_publish_permitted():
    stop = threading.Event()
    def last(*args, **kwargs):
        stop.set()
        return next(r for r in complete_results() if r['id']=='operational_latency')
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider), patch.object(psa, 'probe_reasoning_and_latency_metrics', side_effect=last):
        report = psa.audit_provider(BASE, KEY, 'synthetic', stop_event=stop)
    assert not report['verdict']['memory_permitted']


def test_whitespace_endpoint_not_silently_fixed():
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider) as http:
        report = psa.audit_provider(' '+BASE, KEY, 'synthetic')
    http.assert_not_called()
    assert not report['verdict']['memory_permitted']
