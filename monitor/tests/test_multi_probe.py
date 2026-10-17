"""Exercise actual batch worker offline, without provider credentials."""
import ast
import queue
from pathlib import Path
source=Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
tree=ast.parse(source.read_text(encoding='utf-8'))
batch=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='do_benchmark')
worker=next(n for n in batch.body if isinstance(n,ast.FunctionDef) and n.name=='work')
for rounds in (1,3):
    calls=[]
    env=dict(rounds=rounds,picked=['first','second'],base='http://127.0.0.1',key='synthetic',uiq=queue.Queue(),result_win=None,progress=None,render=None,table=None,probe_btn=None,bench_btn=None)
    env['probe_model']=lambda model,base,key: calls.append(model) or {'ok':True,'ms':1}
    env['benchmark_summary']=lambda model,samples: {'model':model,'median_ms':1,'runs':len(samples)}
    exec(compile(ast.Module(body=[worker],type_ignores=[]),str(source),'exec'),env)
    env['work']()
    assert calls==['first']*rounds+['second']*rounds,calls
    events=list(env['uiq'].queue)
    assert events[-1][0]=='benchmark_done'
    assert all(row['runs']==rounds for row in events[-1][3])
print('MULTI_PROBE_ONE_AND_THREE_ROUNDS_OK')
