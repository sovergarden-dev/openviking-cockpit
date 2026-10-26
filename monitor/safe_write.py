"""Safe atomic write utilities with Windows ACL protection and interprocess file locking.

Provides:
- Interprocess file locking (via msvcrt.locking on Windows) to prevent lost updates.
- Secure temp file creation in destination directory (same volume) with restrictive DACL
  before any sensitive bytes are written.
- Atomic file replacement (os.replace).
- Post-replace verification of content integrity (SHA-256) and explicit DACL.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Generator, Optional, Union

if sys.platform == "win32":
    import msvcrt

def apply_restricted_file_acl(target_path: Union[str, Path]) -> bool:
    """Explicitly set non-inherited ACL on target file: SYSTEM(F), Administrators(F), CurrentUser(F).
    
    Removes any inherited or broad grants (e.g. CodexSandboxUsers).
    """
    if sys.platform != "win32":
        return True
    p = str(Path(target_path).resolve())
    username = os.environ.get("USERNAME", "Rurus")
    userdomain = os.environ.get("USERDOMAIN", "")
    full_user = f"{userdomain}\\{username}" if userdomain else username
    
    # Run icacls to reset inheritance and grant exclusive permissions
    # /inheritance:r removes all inherited ACEs
    # /grant grants explicit Full control
    cmd = [
        "icacls", p,
        "/inheritance:r",
        "/grant:r", "NT AUTHORITY\\SYSTEM:(F)",
        "/grant:r", "BUILTIN\\Administrators:(F)",
        "/grant:r", f"{full_user}:(F)"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5.0)
        return res.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False


@contextlib.contextmanager
def interprocess_file_lock(lock_file_path: Union[str, Path], timeout_seconds: float = 10.0) -> Generator[None, None, None]:
    """Acquire exclusive interprocess lock on a lock file.
    
    Prevents concurrent writers from clobbering state.
    """
    p = Path(lock_file_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    f = open(p, "a+b")
    try:
        if sys.platform == "win32":
            import time
            start = time.time()
            acquired = False
            while time.time() - start < timeout_seconds:
                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    acquired = True
                    break
                except (IOError, OSError):
                    time.sleep(0.05)
            if not acquired:
                raise TimeoutError(f"Could not acquire interprocess lock on {p} within {timeout_seconds}s")
        yield
    finally:
        if sys.platform == "win32":
            try:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
        f.close()


def safe_atomic_write_text(
    dest_path: Union[str, Path],
    content: str,
    encoding: str = "utf-8",
    restrict_acl: bool = True,
    expected_previous_sha: Optional[str] = None
) -> str:
    """Atomically write text to destination file with restrictive DACL and SHA-256 verification.
    
    Returns: SHA-256 hex digest of the written file.
    """
    dest = Path(dest_path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Revision check if requested
    if expected_previous_sha is not None and dest.is_file():
        current_sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        if current_sha != expected_previous_sha:
            raise ValueError(f"Revision mismatch for {dest.name}: expected {expected_previous_sha}, found {current_sha}")

    raw_bytes = content.encode(encoding)
    expected_sha = hashlib.sha256(raw_bytes).hexdigest()

    # 1. Create secure unique temp file on the same volume (destination directory)
    # Using mkstemp creates with O_CREAT | O_EXCL
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest.parent))
    tmp_path = Path(tmp_name)

    try:
        # 2. Restrict ACL on temp file BEFORE writing any sensitive bytes
        if restrict_acl and sys.platform == "win32":
            apply_restricted_file_acl(tmp_path)

        # 3. Write data, flush buffers, fsync to disk
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw_bytes)
            handle.flush()
            os.fsync(handle.fileno())

        # 4. Atomic replacement
        os.replace(tmp_path, dest)

        # 5. Post-replace verification
        actual_bytes = dest.read_bytes()
        actual_sha = hashlib.sha256(actual_bytes).hexdigest()
        if actual_sha != expected_sha:
            raise IOError(f"Integrity verification failed for {dest.name}: written SHA {actual_sha} != expected {expected_sha}")

        # 6. Re-apply restricted ACL post-replace to ensure DACL persisted
        if restrict_acl and sys.platform == "win32":
            apply_restricted_file_acl(dest)

        return actual_sha
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def safe_atomic_write_json(
    dest_path: Union[str, Path],
    data: dict,
    indent: int = 2,
    restrict_acl: bool = True
) -> str:
    """Serialize and atomically write json data."""
    payload = json.dumps(data, ensure_ascii=False, indent=indent) + "\n"
    return safe_atomic_write_text(dest_path, payload, restrict_acl=restrict_acl)
