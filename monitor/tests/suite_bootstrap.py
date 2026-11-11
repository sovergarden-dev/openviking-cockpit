"""Execute a suite with fake Monitor state and no live service connections."""
import ast
import json
import os
from pathlib import Path
import runpy
import socket
import sys
import tempfile
import time


def main():
    path = Path(sys.argv[1]).resolve()
    caller_home = os.environ.get('USERPROFILE')
    local = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData/Local')
    scratch = Path(os.environ.get('TMPDIR') or local / 'hermes/cache/scratch')
    if scratch.resolve() == (local / 'Temp').resolve():
        scratch = local / 'hermes/cache/scratch'
    scratch.mkdir(parents=True, exist_ok=True)
    isolation = tempfile.TemporaryDirectory(prefix='ov-suite-', dir=scratch)
    home = Path(isolation.name) / 'home'
    ov = home / '.openviking'
    (ov / 'monitor').mkdir(parents=True)
    (ov / 'logs').mkdir()
    config = {'vlm': {'model': 'fixture-model', 'api_base': 'http://127.0.0.1:9/v1',
                      'api_key': 'fixture-key', 'thinking': True, 'max_retries': 2,
                      'failback_timeout_seconds': 3600, 'failback_request_count': 10},
              'embedding': {'dense': {'model': 'qwen3-embedding:0.6b'}}}
    state = {'run_with_windows': False, 'notify_on_down': False, 'notify_on_failover': False,
             'auto_probe_enabled': False, 'geometry': '1020x800',
             'spare_models': [{'model': 'fixture-model', 'api_base': 'http://127.0.0.1:9/v1',
                               'api_key': 'fixture-key', 'note': ''}]}
    (ov / 'ov.conf').write_text(json.dumps(config), encoding='utf-8')
    (ov / 'monitor/monitor.json').write_text(json.dumps(state), encoding='utf-8')
    (ov / 'logs/server.log').write_text('', encoding='utf-8')
    import shutil
    shutil.copy2(Path(__file__).resolve().parents[1] / 'openviking.ico', ov / 'monitor/openviking.ico')
    protected = {Path(caller_home or Path.home()).resolve() / '.openviking'}
    if local.name.casefold() == 'local' and local.parent.name.casefold() == 'appdata':
        protected.add(local.parent.parent.resolve() / '.openviking')
    def protect_live(event, args):
        paths = args[:2] if event in {'os.rename', 'os.link', 'os.symlink'} else args[:1]
        if event not in {'open', 'os.rename', 'os.link', 'os.symlink', 'os.remove',
                         'os.rmdir', 'os.mkdir', 'os.chmod', 'os.utime', 'os.listdir', 'os.scandir'}:
            return
        for value in paths:
            if isinstance(value, (str, bytes, os.PathLike)):
                candidate = Path(os.fsdecode(value)).resolve()
                if any(candidate.is_relative_to(root) for root in protected):
                    raise PermissionError('Test filesystem boundary: live OpenViking access blocked')
    sys.addaudithook(protect_live)
    os.environ['USERPROFILE'] = str(home)
    source = path.read_text(encoding='utf-8-sig')
    tree = ast.parse(source)
    uses_pytest = any(isinstance(node, (ast.Import, ast.ImportFrom)) and
                      ((isinstance(node, ast.Import) and any(item.name == 'pytest' for item in node.names)) or
                       (isinstance(node, ast.ImportFrom) and node.module == 'pytest')) for node in tree.body)
    actual_run = runpy.run_path
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex
    blocked_ports = {19330,19335,21434,20128,9100,9101,8100,11434,11435}
    def safe_connect(sock, address):
        if isinstance(address, tuple) and (address[0] not in ('127.0.0.1','::1','localhost') or address[1] in blocked_ports):
            raise OSError('Test network boundary: live/remote connection blocked')
        return original_connect(sock,address)
    def safe_connect_ex(sock,address):
        try:
            safe_connect(sock,address)
            return 0
        except OSError:
            return 10061
    socket.socket.connect = safe_connect
    socket.socket.connect_ex = safe_connect_ex
    def isolated_run(file, *args, **kwargs):
        namespace = actual_run(file,*args,**kwargs)
        if Path(file).name != 'openviking-monitor.pyw':
            return namespace
        glob = namespace['run_gui'].__globals__
        def fake_collect(include_ready=False):
            conf=glob['read_ov_conf']()
            return {'ts':time.time(),'elapsed_ms':1,'health_code':200,'health':{'healthy':True,'version':'fixture'},
                    'ov_up':True,'version':'fixture','ollama_up':True,'gateway_up':True,'gateway_http':True,
                    'queue':{},'vectors':{'count':10},'usage':{},'retrieval':{},'conf':conf,
                    'listeners':{'ov':[{'pid':'4242','addr':'127.0.0.1:19330'}],'ollama':[],'gateway':[]},
                    'task':{'status':'Ready','last_result':'0'},'issues':[],'failover':False,'active':0,
                    'live':{'index':0,'n':1,'manual_hold':False,'credential_ids':['credential-0']},'failover_detail':'',
                    'ov_down_since':None,'ov_procs':None}
        def no_probe(*args,**kwargs):
            raise RuntimeError('Real provider probes forbidden in tests')
        glob.update(collect=fake_collect,run_hidden=lambda *a,**k:(0,''),
                    set_run_with_windows=lambda enabled:None,probe_model=no_probe,
                    list_chat_models=no_probe)
        class FakeTray:
            hwnd=0
            added=False
            def add(self,*a,**k):return False
            def remove(self,*a,**k):pass
            def __init__(self,*a,**k):pass
            def create(self,*a,**k):return False
            def update(self,*a,**k):pass
            def balloon(self,*a,**k):pass
            def destroy(self,*a,**k):pass
        glob['Tray']=FakeTray
        namespace.update({k:glob[k] for k in ('collect','run_hidden','set_run_with_windows','probe_model','list_chat_models','Tray')})
        return namespace
    runpy.run_path=isolated_run
    sys.path.insert(0,str(path.parent))
    sys.argv=[str(path)]
    try:
        if uses_pytest:
            import pytest
            return pytest.main(['-q','-p','no:cacheprovider','--rootdir',str(path.parent),str(path)])
        actual_run(str(path),run_name='__main__')
        return 0
    finally:
        runpy.run_path=actual_run
        socket.socket.connect=original_connect
        socket.socket.connect_ex=original_connect_ex
        if caller_home is None:
            os.environ.pop('USERPROFILE', None)
        else:
            os.environ['USERPROFILE'] = caller_home
        isolation.cleanup()

if __name__=='__main__':
    raise SystemExit(main())
