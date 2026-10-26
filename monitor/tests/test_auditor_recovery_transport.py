import io
import json
import threading
import urllib.error
from email.message import Message
from unittest.mock import patch, MagicMock
import pytest
from test_auditor_recovery import psa, isolated, BASE, KEY, response, fake_provider

class Reply(io.BytesIO):
    status = 200
    def __init__(self, data, lengths=(), read_error=False, tick=None):
        super().__init__(data)
        self.headers = Message()
        for value in lengths:
            self.headers.add_header('Content-Length', value)
        self.read_error = read_error
        self.tick = tick
    def read(self, n=-1):
        assert n > 0
        if self.tick:
            self.tick[0] += 2
        if self.read_error:
            raise OSError('synthetic broken read')
        return super().read(n)
    read1 = read

@pytest.mark.parametrize('url', ['http://example.invalid/v1', 'ftp://localhost/v1',
    'https://user:pass@example.invalid/v1', 'https://example.invalid/v1?q=1',
    'https://example.invalid/v1#x', ' https://example.invalid/v1',
    'https://example.invalid:99999/v1', 'https://example.invalid:/v1',
    'https://example.invalid:0/v1', 'https://example.invalid/v1?',
    'https://example.invalid\\evil/v1'])
def test_direct_http_rejects_unsafe_endpoint_before_auth(url):
    with patch.object(psa.urllib.request, 'build_opener') as build:
        status, body, raw, elapsed = psa.execute_bounded_http(url, headers={'Authorization':'Bearer '+KEY})
    assert body is None
    assert status is None
    build.assert_not_called()

@pytest.mark.parametrize('data,lengths', [
    (b'{}', ['3']), (b'{}', ['1']), (b'{}', ['-1']), (b'{}', ['abc']),
    (b'{}', ['2','2']), (b'{}', ['2,2']), (b'{}', ['9999999']),
    (b'{"a":"\xff"}', []), (b'['*40+b'0'+b']'*40, []),
    (b'{"a":1,"a":2}', []), (b'x'*65537, []),
], ids=['short','long','negative','nonnumeric','duplicate','comma','oversize-header','utf8','depth','duplicate-json','oversize-body'])
def test_bounded_http_rejects_incomplete_invalid_body(data, lengths):
    reply = Reply(data, lengths)
    opener = MagicMock()
    opener.open.return_value = reply
    with patch.object(psa.urllib.request, 'build_opener', return_value=opener):
        result = psa.execute_bounded_http(BASE)
    assert result[1] is None
    assert reply.closed


def test_elapsed_includes_body_read_and_wall_deadline():
    clock = [0.0]
    opener = MagicMock()
    reply = Reply(b'{}', tick=clock)
    opener.open.return_value = reply
    with patch.object(psa.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(psa.urllib.request, 'build_opener', return_value=opener):
        result = psa.execute_bounded_http(BASE, timeout=1)
    assert result[1] is None
    assert result[3] >= 2000
    assert reply.closed


def test_error_body_read_failure_closed_not_raised():
    reply = Reply(b'', read_error=True)
    error = urllib.error.HTTPError(BASE, 500, 'synthetic', {}, reply)
    opener = MagicMock()
    opener.open.side_effect = error
    with patch.object(psa.urllib.request, 'build_opener', return_value=opener):
        result = psa.execute_bounded_http(BASE)
    assert result[1] is None
    assert reply.closed


def test_valid_http_uses_no_proxy_no_redirect():
    opener = MagicMock()
    opener.open.return_value = Reply(b'{}', ['2'])
    with patch.object(psa.urllib.request, 'build_opener', return_value=opener) as build:
        assert psa.execute_bounded_http('http://127.0.0.1:1234/Case')[1] == {}
    handlers = build.call_args.args
    assert any(isinstance(h, psa.urllib.request.ProxyHandler) and h.proxies == {} for h in handlers)
    assert any(isinstance(h, psa.NoRedirectHandler) for h in handlers)
