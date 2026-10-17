"""Stale-lock guard: keep only a real OpenViking owner; remove everything else."""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HOME = Path(os.environ.get("USERPROFILE", r"C:\Users\rurus"))
GUARD = HOME / ".openviking" / "ov_stale_lock_clean.py"
VENV_PY = HOME / ".openviking" / "venv" / "Scripts" / "python.exe"
SYSTEM_PY = Path(sys.executable)
MARKER = str(HOME / ".openviking" / "venv" / "Scripts" / "openviking-server.exe")

BASE = Path(os.environ.get("TMPDIR") or HOME / "AppData/Local/hermes/cache/scratch") / "ov_guard_test"
if BASE.exists():
    shutil.rmtree(BASE)
BASE.mkdir(parents=True)

assert VENV_PY.exists(), f"venv python missing: {VENV_PY}"
assert not str(SYSTEM_PY).lower().startswith(str(HOME / ".openviking" / "venv").lower()), \
    "run the suite with a non-venv python for the foreign-process cases"


def run_guard(lock: Path):
    return subprocess.run([str(SYSTEM_PY), str(GUARD), str(lock)],
                          capture_output=True, text=True, timeout=60)


def wait_file(path: Path, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        if path.exists() and path.read_text(encoding="utf-8").strip().isdigit():
            return True
        time.sleep(0.25)
    return False


def kill_tree(pid):
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                   capture_output=True, text=True, timeout=15)


# T1: no file -> no-op
missing = BASE / "none.pid"
r = run_guard(missing)
assert r.returncode == 0 and not missing.exists(), "T1"

# T2: dead/invalid pid -> removed
f2 = BASE / "f2.pid"
f2.write_text("99999999", encoding="utf-8")
run_guard(f2)
assert not f2.exists(), "T2 dead pid not removed"

# T3: live FOREIGN python -> removed
f3 = BASE / "f3.pid"
code3 = f"import os,time; open(r'{f3}','w').write(str(os.getpid())); time.sleep(40)"
child = subprocess.Popen([str(SYSTEM_PY), "-c", code3])
try:
    assert wait_file(f3), "T3 child never wrote pid"
    run_guard(f3)
    assert not f3.exists(), "T3 foreign live pid not removed"
finally:
    kill_tree(child.pid)

# T4: real-owner shape (cmdline carries openviking-server) -> kept
f4 = BASE / "f4.pid"
code4 = f"import os,time; open(r'{f4}','w').write(str(os.getpid())); time.sleep(40)"
child4 = subprocess.Popen([str(SYSTEM_PY), "-c", code4, MARKER])
try:
    assert wait_file(f4), "T4 child never wrote pid"
    run_guard(f4)
    assert f4.exists(), "T4 real-owner lock wrongly removed"
finally:
    kill_tree(child4.pid)

# T4b: venv redirector chain (grandchild runs the code) -> kept
f4b = BASE / "f4b.pid"
code4b = f"import os,time; open(r'{f4b}','w').write(str(os.getpid())); time.sleep(40)"
child4b = subprocess.Popen([str(VENV_PY), "-c", code4b, MARKER])
try:
    assert wait_file(f4b), "T4b grandchild never wrote pid"
    run_guard(f4b)
    assert f4b.exists(), "T4b venv-chain lock wrongly removed"
finally:
    kill_tree(child4b.pid)
    gp = f4b.read_text(encoding="utf-8").strip() if f4b.exists() else ""
    if gp.isdigit():
        kill_tree(int(gp))

# T5: protected system pid -> removed
f5 = BASE / "f5.pid"
f5.write_text("4", encoding="utf-8")
run_guard(f5)
assert not f5.exists(), "T5 protected pid not removed"

# T6: real production lock (when the server is live) -> kept
real_lock = HOME / ".openviking" / "data-qwen06b" / ".openviking.pid"
if real_lock.is_file():
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:19330/health", timeout=3) as rq:
            healthy = rq.status == 200
    except Exception:
        healthy = False
    if healthy:
        before = real_lock.read_text(encoding="utf-8").strip()
        run_guard(real_lock)
        assert real_lock.is_file() and real_lock.read_text(encoding="utf-8").strip() == before, \
            "T6 live production lock was removed"
        print("T6 live-lock check: KEPT (server running)")
    else:
        print("T6 live-lock check: skipped (server down)")

shutil.rmtree(BASE, ignore_errors=True)
print("STALE_LOCK_GUARD_OK")
