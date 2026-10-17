import ast
from pathlib import Path
from urllib.parse import urlparse
p=Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
t=ast.parse(p.read_text(encoding='utf-8'))
import runpy
runtime = runpy.run_path(str(p))
env={'urlparse':urlparse, 'ssl_context':runtime['ssl_context'], 'http_fail_text':runtime['http_fail_text']}
def fn(name):
    node=next(n for n in ast.walk(t) if isinstance(n,ast.FunctionDef) and n.name==name)
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(p),'exec'),env)
    return env[name]
classify=fn('classify_endpoint')
assert classify('https://api.openai.com/v1')['type']=='official'
assert classify('https://openrouter.ai/api/v1')['type']=='aggregator'
assert classify('http://127.0.0.1:20128/v1')['type']=='local'
assert classify('https://seller.example/v1')['type']=='third-party'
assert classify('ftp://seller.example/v1')['type']=='invalid'
assert classify('https://user:pass@seller.example/v1')['type']=='invalid'
verdict=fn('verification_verdict')
assert verdict({'provider_type':'aggregator','reported_model':'x','requested_model':'x'})['status']=='self-reported'
assert verdict({'provider_type':'official','reported_model':'x','requested_model':'y'})['status']=='inconclusive'
assert any(isinstance(n,ast.FunctionDef) and n.name=='quick_verify' for n in t.body)
src=p.read_text(encoding='utf-8')
assert 'Read-only protocol check' in src
assert 'text="Xác minh"' in src
assert 'quick_verify(model, base' in src
assert 'text="Xác minh"' in src
assert verdict({})['status'] == 'inconclusive'
assert verdict({'provider_type':'official','reported_model':'x','requested_model':'x'})['status'] != 'verified-direct'
print('VERIFY_ENDPOINT_RULES_OK')
print('VERIFY_GUI_WIRING_OK')
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
hits=[]
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        hits.append(self.path)
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/destination')
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"data":[{"id":"synthetic-model"}]}')
server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
try:
    request=fn('verification_http_json')
    base='http://127.0.0.1:'+str(server.server_port)
    assert request(base+'/redirect',headers={'Authorization':'Bearer synthetic'})[0] == 302
    assert '/destination' not in hits
    fn('_model_ids_from_body')
    check=fn('quick_verify')
    result=check('synthetic-model',base,'synthetic')
    assert result['ok'] and result['text']=='Self-reported only'
    assert 'Authorization' not in str(result)
    client=fn('http_json')
    assert client(base+'/redirect', headers={'Authorization':'Bearer synthetic'})[0] == 302
    assert '/destination' not in hits
    before=list(hits)
    assert client('http://seller.example/v1/models', headers={'Authorization':'Bearer synthetic'})[0] is None
    assert hits == before
    print('AUTH_CLIENT_REDIRECT_AND_HTTP_BLOCK_OK')
    print('LIVE_LOOPBACK_REDIRECT_AND_VERIFY_OK')
finally:
    server.shutdown()
    server.server_close()

