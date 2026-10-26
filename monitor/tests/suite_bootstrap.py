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
                    'live':{'index':0,'n':1,'manual_hold':False,'credential_ids':['legacy-primary']},'failover_detail':'',
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
            return pytest.main(['-q','-p','no:cacheprovider',str(path)])
        actual_run(str(path),run_name='__main__')
        return 0
    finally:
        runpy.run_path=actual_run
        socket.socket.connect=original_connect
        socket.socket.connect_ex=original_connect_ex

if __name__=='__main__':
    raise SystemExit(main())
