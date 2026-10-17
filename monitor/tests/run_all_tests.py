"""Run all OpenViking Monitor unit and regression tests."""
import os, subprocess, sys
from pathlib import Path

tests_dir = Path(__file__).resolve().parent
# GUI suites must run on the interpreter the app actually uses (Tk 8.6 on
# Python 3.11): a probe under Tk 9 hid a layout bug that was live on Tk 8.6.
APP_PY = Path(r"C:\Users\rurus\AppData\Local\Programs\Python\Python311\python.exe")
RUNNER = str(APP_PY) if APP_PY.is_file() else sys.executable
# Suites are test_*.py / check_*.py; every other .py here is a helper
# (e.g. switcher_hold_helper.py runs under the venv python, not this one).
test_files = sorted(
    f
    for f in tests_dir.glob("*.py")
    if f.name != "run_all_tests.py"
    and (f.name.startswith("test_") or f.name.startswith("check_"))
)

all_pass = True
print(f"Running {len(test_files)} test suites in {tests_dir}:")
print(f"Interpreter: {RUNNER}")
for tf in test_files:
    env = {**os.environ, "MONITOR_NO_AUTOFIT": "1"}
    res = subprocess.run([RUNNER, str(tf)], capture_output=True, text=True, env=env)
    if res.returncode == 0:
        print(f"  [PASS] {tf.name}")
    else:
        all_pass = False
        print(f"  [FAIL] {tf.name} (exit {res.returncode}):")
        for line in (res.stdout + res.stderr).strip().splitlines():
            print(f"    {line}")

print("\nResult: " + ("ALL PASSED" if all_pass else "FAILURES DETECTED"))
sys.exit(0 if all_pass else 1)
