"""Plan-first source-only Monitor synchronization. Never handles config or data."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import datetime, timezone
import uuid

CORE_FILES = ('openviking-monitor.pyw', 'provider_security_auditor.py',
              'reference_core_v31.py', 'reserve_table.py',
              'openviking_monitor_notification.py', 'openviking.ico')


def sha(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def safe_child(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Unsafe synchronization path: ' + relative)
    if any(parent.is_symlink() for parent in path.parents if parent != root and parent.is_relative_to(root)):
        raise ValueError('Symlinked synchronization directory')
    return path


def make_plan(source: Path, destination: Path) -> dict:
    source, destination = source.resolve(), destination.resolve()
    if not source.is_dir() or not destination.is_dir() or source == destination:
        raise ValueError('Source and destination must be distinct existing directories')
    names = list(CORE_FILES)
    names.extend('tests/' + p.name for p in sorted((source/'tests').glob('*.py')) if p.is_file())
    rows = []
    for name in names:
        src, dest = safe_child(source, name), safe_child(destination, name)
        if not src.is_file():
            raise FileNotFoundError('Required source missing: ' + name)
        source_hash, destination_hash = sha(src), sha(dest)
        rows.append({'path':name, 'source_sha256':source_hash, 'destination_sha256':destination_hash,
                     'changed':source_hash != destination_hash})
    return {'source':str(source), 'destination':str(destination), 'files':rows,
            'changed_count':sum(row['changed'] for row in rows)}


def _publish(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def running_monitors() -> list[dict]:
    if os.name != 'nt':
        raise RuntimeError('Process ownership verification is supported on Windows only')
    script = "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*' -and $_.CommandLine -like '*openviking-monitor.pyw*' -and $_.CommandLine -notlike '*-c *' } | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
    result = subprocess.run(['powershell.exe','-NoProfile','-Command',script],capture_output=True,text=True,timeout=30)
    if result.returncode:
        raise RuntimeError('Cannot verify Monitor process ownership')
    value = json.loads(result.stdout.strip() or '[]')
    return value if isinstance(value, list) else [value]


def assert_monitor_stopped(directory: Path) -> None:
    needle = str(directory/'openviking-monitor.pyw').replace('\\','/').casefold()
    for process in running_monitors():
        if needle in (process.get('CommandLine') or '').replace('\\','/').casefold():
            raise RuntimeError('Monitor still running; close only that GUI before applying source changes')


def apply_plan(plan: dict, backup_root: Path, *, check_running: bool = True) -> dict:
    source, dest = Path(plan['source']), Path(plan['destination'])
    fresh = make_plan(source, dest)
    if fresh != plan:
        raise RuntimeError('Source or destination drift: regenerate and review the plan')
    if not plan['changed_count']:
        return {'status':'unchanged', 'changed_count':0, 'files':plan['files']}
    if check_running:
        assert_monitor_stopped(dest)
    backup = backup_root / ('monitor-sync-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    backup.mkdir(parents=True, exist_ok=False)
    changed = [row for row in plan['files'] if row['changed']]
    payloads = {}
    for row in changed:
        name = row['path']
        src, target = safe_child(source,name), safe_child(dest,name)
        payloads[name] = src.read_bytes()
        if hashlib.sha256(payloads[name]).hexdigest() != row['source_sha256'] or sha(target) != row['destination_sha256']:
            raise RuntimeError('Concurrent source/destination drift before backup')
        if target.is_file():
            _publish(backup/'original'/name,target.read_bytes())
            if sha(backup/'original'/name) != row['destination_sha256']:
                raise RuntimeError('Backup verification failed')
    receipt = dict(plan, status='prepared', backup=str(backup))
    _publish(backup/'receipt.json', json.dumps(receipt,indent=2).encode())
    applied=[]
    try:
        if check_running:
            assert_monitor_stopped(dest)
        for row in changed:
            name=row['path'];target=safe_child(dest,name)
            if sha(target) != row['destination_sha256']:
                raise RuntimeError('Concurrent destination drift during publish')
            applied.append(row)
            _publish(target,payloads[name])
            if sha(target) != row['source_sha256']:
                raise RuntimeError('Post-write verification failed')
        receipt['status']='applied'
        _publish(backup/'receipt.json',json.dumps(receipt,indent=2).encode())
    except Exception as exc:
        failures=[]
        for row in reversed(applied):
            target=safe_child(dest,row['path'])
            try:
                if row['destination_sha256'] is None:
                    target.unlink(missing_ok=True)
                else:
                    _publish(target,(backup/'original'/row['path']).read_bytes())
                if sha(target)!=row['destination_sha256']:
                    raise RuntimeError('Rollback verification failed')
            except (OSError,RuntimeError) as rollback_error:
                failures.append({'path':row['path'],'error':type(rollback_error).__name__})
        receipt.update(status='rollback_failed' if failures else 'rolled_back', rollback_failures=failures)
        _publish(backup/'receipt.json',json.dumps(receipt,indent=2).encode())
        raise RuntimeError(('Rollback failed; inspect ' if failures else 'Publish failed; rolled back; inspect ') + str(backup)) from exc
    return receipt


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('direction',choices=['deploy','pull'])
    parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--live',type=Path,default=Path.home()/'.openviking/monitor')
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    source,dest=(args.repo/'monitor',args.live) if args.direction=='deploy' else (args.live,args.repo/'monitor')
    plan=make_plan(source,dest)
    if args.apply:
        if args.direction=='pull':
            result=subprocess.run(['git','-C',str(args.repo),'status','--porcelain','--','monitor'],capture_output=True,text=True,timeout=15,check=True)
            if result.stdout.strip():
                raise RuntimeError('Refusing to overwrite dirty repo monitor files; reconcile first')
        receipt=apply_plan(plan,args.live.parent/'backups',check_running=args.direction=='deploy')
        print(json.dumps(receipt,ensure_ascii=True,indent=2))
    else:
        print('PLAN ONLY: no files changed. Use --apply after verification.')
        print(json.dumps(plan,ensure_ascii=True,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
