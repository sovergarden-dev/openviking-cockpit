r"""Remove a stale OpenViking data-directory lock before server startup.

OpenViking's Windows PID check only tests whether the PID in `data-qwen06b/.openviking.pid` is alive, not whether that process is actually `openviking-server`. After a reboot Windows can recycle the PID onto an unrelated system process (causing a `DataDirectoryLocked` exit-code-3 crash loop). This guard keeps the lock only when the PID is alive AND its executable or command line belongs to OpenViking; exit code is always 0.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

HOME = Path(os.environ["USERPROFILE"]) if os.environ.get("USERPROFILE") else Path.home()
DEFAULT_LOCK = HOME / ".openviking" / "data-qwen06b" / ".openviking.pid"

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
CREATE_NO_WINDOW = 0x08000000

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
_k32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]

OWNER_EXES = {"openviking-server.exe", "openviking.exe"}


def read_pid(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def _image_path(pid: int) -> str:
    handle = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(4096)
        buf = ctypes.create_unicode_buffer(size.value)
        if not _k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return ""
        return buf.value
    finally:
        _k32.CloseHandle(handle)


def _cmdline(pid: int) -> str | None:
    try:
        r = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return (r.stdout or "").strip()


def looks_like_openviking(cmdline: str) -> bool:
    low = cmdline.casefold().replace("/", "\\")
    return "openviking-server" in low or ".openviking\\venv" in low


def is_real_owner(pid: int) -> bool:
    if pid <= 0:
        return False
    path = _image_path(pid)
    if not path:
        return False
    if os.path.basename(path).casefold() in OWNER_EXES:
        return True
    cl = _cmdline(pid)
    if cl is None:
        # Fail-closed when process command line cannot be queried: preserve existing lock.
        return True
    if not cl:
        return False
    return looks_like_openviking(cl)


def main(argv: list[str]) -> int:
    lock_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_LOCK
    try:
        if not lock_path.is_file():
            return 0
        pid = read_pid(lock_path)
        if pid > 0 and is_real_owner(pid):
            return 0
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
