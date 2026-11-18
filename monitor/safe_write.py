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
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Generator, Optional, Union

if sys.platform == "win32":
    import msvcrt

    _TOKEN_QUERY = 0x0008
    _TOKEN_USER_CLASS = 1
    _SDDL_REVISION_1 = 1
    _SE_FILE_OBJECT = 1
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _SE_DACL_PROTECTED = 0x1000
    _ACL_SIZE_INFORMATION_CLASS = 2
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _FILE_ALL_ACCESS = 0x001F01FF

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class _TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", _SID_AND_ATTRIBUTES)]

    class _ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.GetCurrentProcess.argtypes = []
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.LocalFree.argtypes = [wintypes.HLOCAL]
    _k32.LocalFree.restype = wintypes.HLOCAL

    _adv32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _adv32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _adv32.OpenProcessToken.restype = wintypes.BOOL
    _adv32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _adv32.GetTokenInformation.restype = wintypes.BOOL
    _adv32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _adv32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _adv32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _adv32.ConvertStringSidToSidW.restype = wintypes.BOOL
    _adv32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _adv32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _adv32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _adv32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    _adv32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    _adv32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    _adv32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _adv32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    _adv32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _adv32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _adv32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _adv32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    _adv32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    _adv32.GetAclInformation.restype = wintypes.BOOL
    _adv32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _adv32.GetAce.restype = wintypes.BOOL
    _adv32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _adv32.EqualSid.restype = wintypes.BOOL

    def _current_user_sid_string() -> Optional[str]:
        token = wintypes.HANDLE()
        if not _adv32.OpenProcessToken(_k32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
            return None
        try:
            needed = wintypes.DWORD(0)
            _adv32.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
            if needed.value == 0:
                return None
            qwords = (needed.value + 7) // 8
            buf = (ctypes.c_uint64 * qwords)()
            if not _adv32.GetTokenInformation(
                token, _TOKEN_USER_CLASS, buf, needed.value, ctypes.byref(needed)
            ):
                return None
            tu = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
            sid_ptr = ctypes.c_void_p()
            if not _adv32.ConvertSidToStringSidW(tu.User.Sid, ctypes.byref(sid_ptr)):
                return None
            try:
                return ctypes.wstring_at(sid_ptr.value)
            finally:
                _k32.LocalFree(sid_ptr.value)
        finally:
            _k32.CloseHandle(token)


def inspect_file_acl(target_path: Union[str, Path]) -> dict:
    """Read Windows DACL state via Win32 advapi32 without spawning PowerShell."""
    resolved_str = str(Path(target_path).resolve())
    if sys.platform != "win32":
        return {"path": resolved_str, "protected": True, "exact_dacl": True, "sddl_access": ""}
    if not os.path.exists(resolved_str):
        raise FileNotFoundError(resolved_str)
    user_sid = _current_user_sid_string()
    if not user_sid:
        raise OSError("Unable to resolve current process token SID")

    read_dacl = ctypes.c_void_p()
    read_sd = ctypes.c_void_p()
    rc_get = _adv32.GetNamedSecurityInfoW(
        resolved_str,
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(read_dacl),
        None,
        ctypes.byref(read_sd),
    )
    if rc_get != 0 or not read_sd.value or not read_dacl.value:
        if read_sd.value:
            _k32.LocalFree(read_sd.value)
        raise OSError(f"GetNamedSecurityInfoW failed with error {rc_get}")

    required_sids: list[ctypes.c_void_p] = []
    owner_rights_sid = ctypes.c_void_p()
    sddl_ptr = ctypes.c_void_p()
    try:
        ctrl = wintypes.WORD(0)
        rev = wintypes.DWORD(0)
        if not _adv32.GetSecurityDescriptorControl(
            read_sd, ctypes.byref(ctrl), ctypes.byref(rev)
        ):
            raise OSError("GetSecurityDescriptorControl failed")
        protected = bool(ctrl.value & _SE_DACL_PROTECTED)

        if not _adv32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            read_sd,
            _SDDL_REVISION_1,
            _DACL_SECURITY_INFORMATION,
            ctypes.byref(sddl_ptr),
            None,
        ) or not sddl_ptr.value:
            raise OSError("ConvertSecurityDescriptorToStringSecurityDescriptorW failed")
        sddl_access = ctypes.wstring_at(sddl_ptr.value)

        for sid_str in dict.fromkeys(("S-1-5-18", "S-1-5-32-544", user_sid)):
            psid = ctypes.c_void_p()
            if not _adv32.ConvertStringSidToSidW(sid_str, ctypes.byref(psid)):
                raise OSError("ConvertStringSidToSidW failed")
            required_sids.append(psid)
        _adv32.ConvertStringSidToSidW("S-1-3-4", ctypes.byref(owner_rights_sid))

        info = _ACL_SIZE_INFORMATION()
        if not _adv32.GetAclInformation(
            read_dacl,
            ctypes.byref(info),
            ctypes.sizeof(info),
            _ACL_SIZE_INFORMATION_CLASS,
        ):
            raise OSError("GetAclInformation failed")

        matched = [False] * len(required_sids)
        all_aces_valid = info.AceCount > 0
        for idx in range(info.AceCount):
            ace_ptr = ctypes.c_void_p()
            if not _adv32.GetAce(read_dacl, idx, ctypes.byref(ace_ptr)) or not ace_ptr.value:
                all_aces_valid = False
                break
            addr = ace_ptr.value
            ace_type = ctypes.c_ubyte.from_address(addr).value
            ace_mask = wintypes.DWORD.from_address(addr + 4).value
            ace_sid = ctypes.c_void_p(addr + 8)
            if ace_type != _ACCESS_ALLOWED_ACE_TYPE or (ace_mask & _FILE_ALL_ACCESS) != _FILE_ALL_ACCESS:
                all_aces_valid = False
                break
            hit = False
            for e_idx, req_sid in enumerate(required_sids):
                if _adv32.EqualSid(ace_sid, req_sid):
                    matched[e_idx] = True
                    hit = True
            if not hit and owner_rights_sid.value and _adv32.EqualSid(ace_sid, owner_rights_sid):
                hit = True
            if not hit:
                all_aces_valid = False
                break

        exact_dacl = bool(protected and all_aces_valid and all(matched))
        return {
            "path": resolved_str,
            "protected": protected,
            "exact_dacl": exact_dacl,
            "sddl_access": sddl_access,
        }
    finally:
        if sddl_ptr.value:
            _k32.LocalFree(sddl_ptr.value)
        if owner_rights_sid.value:
            _k32.LocalFree(owner_rights_sid.value)
        for psid in required_sids:
            if psid.value:
                _k32.LocalFree(psid.value)
        _k32.LocalFree(read_sd.value)


def apply_restricted_file_acl(target_path: Union[str, Path]) -> bool:
    """Explicitly set non-inherited ACL on target file: SYSTEM(F), Administrators(F), CurrentUser(F)."""
    if sys.platform != "win32":
        return True
    try:
        resolved_str = str(Path(target_path).absolute())
        if not os.path.exists(resolved_str):
            return False
        user_sid = _current_user_sid_string()
        if not user_sid:
            return False

        sddl = f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user_sid})"
        sec_desc = ctypes.c_void_p()
        if not _adv32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(sec_desc), None
        ):
            return False
        try:
            present = wintypes.BOOL(0)
            dacl_ptr = ctypes.c_void_p()
            defaulted = wintypes.BOOL(0)
            if not _adv32.GetSecurityDescriptorDacl(
                sec_desc, ctypes.byref(present), ctypes.byref(dacl_ptr), ctypes.byref(defaulted)
            ) or not present.value:
                return False
            rc = _adv32.SetNamedSecurityInfoW(
                resolved_str,
                _SE_FILE_OBJECT,
                _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                dacl_ptr,
                None,
            )
            if rc != 0:
                return False
        finally:
            _k32.LocalFree(sec_desc.value)

        verified = inspect_file_acl(resolved_str)
        return bool(verified["protected"] and verified["exact_dacl"])
    except OSError:
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

    fd_closed = False
    try:
        # 2. Restrict ACL on temp file BEFORE writing any sensitive bytes (fail-closed)
        if restrict_acl and sys.platform == "win32":
            if not apply_restricted_file_acl(tmp_path):
                raise PermissionError(f"Failed to enforce restricted staging ACL on {dest.name}")

        # 3. Write data, flush buffers, fsync to disk
        fd_closed = True
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
            if not apply_restricted_file_acl(dest):
                raise PermissionError(f"Failed to verify restricted destination ACL on {dest.name}")

        return actual_sha
    finally:
        if not fd_closed:
            try:
                os.close(fd)
            except OSError:
                pass
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
