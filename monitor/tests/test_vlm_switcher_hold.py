"""Switcher hold checks under the venv Python; fails loudly if the patch is gone."""
import os
import subprocess
from pathlib import Path

HOME = Path(os.environ.get("USERPROFILE", r"C:\Users\rurus"))
VENV_PY = HOME / ".openviking" / "venv" / "Scripts" / "python.exe"
HELPER = Path(__file__).resolve().parent / "switcher_hold_helper.py"

assert VENV_PY.is_file(), f"venv python missing: {VENV_PY}"

r = subprocess.run([str(VENV_PY), str(HELPER)], capture_output=True, text=True, timeout=120)
assert r.returncode == 0, f"helper failed rc={r.returncode}\n{r.stdout}\n{r.stderr}"
assert "SWITCHER_HOLD_ALL_OK" in r.stdout, r.stdout + r.stderr
for line in r.stdout.splitlines():
    assert not line.startswith("CHECK_FAIL"), line

print("SWITCHER_HOLD_TEST_OK")
