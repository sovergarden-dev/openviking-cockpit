"""Run isolated Monitor suites on Python 3.11; runtime helpers opt in."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-helpers',action='store_true',help='Test installed switcher and legacy PID guard using scratch PID files only')
    parser.add_argument('--output-dir',type=Path)
    args=parser.parse_args()
    tests_dir=Path(__file__).resolve().parent
    real_home=Path(os.environ.get('USERPROFILE',str(Path.home())))
    app_py=Path(os.environ.get('LOCALAPPDATA',str(real_home/'AppData/Local')))/'Programs/Python/Python311/python.exe'
    if not app_py.is_file():
        parser.error('Application Python 3.11 is required; refusing interpreter fallback')
    scratch=real_home/'AppData/Local/hermes/cache/scratch'
    scratch.mkdir(parents=True,exist_ok=True)
    output=args.output_dir or Path(tempfile.mkdtemp(prefix='ov-monitor-tests-',dir=scratch))
    output.mkdir(parents=True,exist_ok=True)
    fake_home=output/'home'
    ov=fake_home/'.openviking'
    (ov/'monitor').mkdir(parents=True,exist_ok=True)
    (ov/'logs').mkdir(exist_ok=True)
    config={'vlm':{'model':'fixture-model','api_base':'http://127.0.0.1:9/v1','api_key':'fixture-key','thinking':True,'max_retries':2,'failback_timeout_seconds':3600,'failback_request_count':10},'embedding':{'dense':{'model':'qwen3-embedding:0.6b'}}}
    (ov/'ov.conf').write_text(json.dumps(config),encoding='utf-8')
    (ov/'monitor/monitor.json').write_text(json.dumps({'run_with_windows':False,'notify_on_down':False,'notify_on_failover':False,'auto_probe_enabled':False,'geometry':'1020x800','spare_models':[{'model':'fixture-model','api_base':'http://127.0.0.1:9/v1','api_key':'fixture-key','note':''}]}),encoding='utf-8')
    shutil.copy2(tests_dir.parent/'openviking.ico',ov/'monitor/openviking.ico')
    (ov/'logs/server.log').write_text('',encoding='utf-8')
    files=sorted(p for p in tests_dir.glob('*.py') if p.name.startswith(('test_','check_')))
    scripts_tests_dir = tests_dir.parents[1] / 'scripts' / 'tests'
    if scripts_tests_dir.is_dir():
        files.extend(sorted(p for p in scripts_tests_dir.glob('*.py') if p.name.startswith('test_')))
    if not files:
        parser.error('No suites discovered')
    print('Interpreter:',app_py,flush=True)
    print('Isolation:',output,flush=True)
    results=[]
    for test in files:
        helper=test.name in {'test_stale_lock_guard.py','test_vlm_switcher_hold.py'}
        if helper and not args.runtime_helpers:
            results.append({'name':test.name,'status':'SKIP','reason':'runtime helper opt-in'})
            print('[SKIP]',test.name,flush=True)
            continue
        env=dict(os.environ, USERPROFILE=str(real_home if helper else fake_home),
                 TMPDIR=str(output),TMP=str(output),TEMP=str(output),PYTHONIOENCODING='utf-8',
                 PYTHONOPTIMIZE='',PYTHONDONTWRITEBYTECODE='1',PYTHONPYCACHEPREFIX=str(output/'pycache'),
                 PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',PYTHONUTF8='1')
        if test.name == 'check_layout_runtime.py':
            env.pop('MONITOR_NO_AUTOFIT', None)
        else:
            env['MONITOR_NO_AUTOFIT'] = '1'
        command=[str(app_py),str(test)] if helper else [str(app_py),str(tests_dir/'suite_bootstrap.py'),str(test)]
        start=time.monotonic()
        child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,text=True,encoding='utf-8',errors='replace')
        try:
            text,_=child.communicate(timeout=150)
            status='PASS' if child.returncode==0 else 'FAIL'
        except subprocess.TimeoutExpired:
            subprocess.run(['taskkill','/PID',str(child.pid),'/T','/F'],capture_output=True,timeout=20)
            text,_=child.communicate(timeout=20)
            status='TIMEOUT'
        (output/(test.stem+'.log')).write_text(text,encoding='utf-8')
        results.append({'name':test.name,'status':status,'exit_code':child.returncode,'seconds':round(time.monotonic()-start,3)})
        (output/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        print('['+status+']',test.name,flush=True)
        if status!='PASS':print(text[-5000:],flush=True)
    counts={key:sum(row['status']==key for row in results) for key in ['PASS','FAIL','SKIP','TIMEOUT']}
    (output/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    print('TOTAL',len(results),json.dumps(counts),flush=True)
    return 1 if counts['FAIL'] or counts['TIMEOUT'] else 0

if __name__=='__main__':
    raise SystemExit(main())
