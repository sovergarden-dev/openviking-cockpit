"""Secure secret storage for OpenViking Cockpit on Windows 11.

Provides:
- 64-bit safe Windows DPAPI encryption with strict ctypes prototypes.
- Fail-loud error handling (never returns ciphertext as key, never returns empty string on decrypt error).
- Typed resolution status: SECRET_READY, DPAPI_UNAVAILABLE, MISSING_ENVIRONMENT_VARIABLE, EMPTY_ENVIRONMENT_VARIABLE, INVALID_SECRET_REFERENCE.
- Strict environment variable reference parser: ^\\$\\{[A-Za-z_][A-Za-z0-9_]*\\}$ (full-string only).
"""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import enum
import os
import re
import sys
from typing import NamedTuple, Optional

# Strict full-string environment variable reference regex
ENV_REF_PATTERN = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")

# Malformed pattern: strict anchors for leading $ or % or embedded Bearer ${
MALFORMED_ENV_PATTERN = re.compile(
    r"^(?:\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|Bearer\s+\$\{[A-Za-z0-9_]+\}|\$\{.*[^\}\s])$"
)

class SecretStatus(enum.Enum):
    SECRET_READY = "SECRET_READY"
    DPAPI_UNAVAILABLE = "DPAPI_UNAVAILABLE"
    MISSING_ENVIRONMENT_VARIABLE = "MISSING_ENVIRONMENT_VARIABLE"
    EMPTY_ENVIRONMENT_VARIABLE = "EMPTY_ENVIRONMENT_VARIABLE"
    INVALID_SECRET_REFERENCE = "INVALID_SECRET_REFERENCE"
    EMPTY_SECRET = "EMPTY_SECRET"

class ResolvedSecret(NamedTuple):
    status: SecretStatus
    value: str
    error_message: Optional[str] = None
    env_var_name: Optional[str] = None

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

_CryptProtectData = None
_CryptUnprotectData = None
_LocalFree = None

if sys.platform == "win32":
    try:
        _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        _CryptProtectData = _crypt32.CryptProtectData
        _CryptProtectData.argtypes = [
            ctypes.POINTER(_DATA_BLOB),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DATA_BLOB),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DATA_BLOB)
        ]
        _CryptProtectData.restype = wintypes.BOOL

        _CryptUnprotectData = _crypt32.CryptUnprotectData
        _CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DATA_BLOB),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DATA_BLOB),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DATA_BLOB)
        ]
        _CryptUnprotectData.restype = wintypes.BOOL

        _LocalFree = _kernel32.LocalFree
        _LocalFree.argtypes = [wintypes.HLOCAL]
        _LocalFree.restype = wintypes.HLOCAL
    except Exception:
        pass


def is_env_ref(text: str) -> bool:
    """Check if text is an explicit environment reference ${NAME}."""
    return bool(isinstance(text, str) and ENV_REF_PATTERN.match(text.strip()))


def get_env_var_name(text: str) -> Optional[str]:
    """Extract environment variable name from ${NAME}."""
    if not isinstance(text, str):
        return None
    m = ENV_REF_PATTERN.match(text.strip())
    return m.group(1) if m else None


def dpapi_protect(text: str, description: str = "OpenViking DPAPI") -> str:
    """Protect plaintext secret using Windows DPAPI.
    
    Fail-loud: Raises RuntimeError if DPAPI fails. Never returns plaintext on error.
    """
    if not text:
        return ""
    if text.startswith("dpapi:"):
        return text
    if sys.platform != "win32" or _CryptProtectData is None:
        raise RuntimeError("DPAPI is only supported on Windows with crypt32 available")

    data = text.encode("utf-8")
    buf = ctypes.create_string_buffer(data)
    in_blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = _DATA_BLOB()
    ctypes.set_last_error(0)
    # CRYPTPROTECT_UI_FORBIDDEN = 1
    if not _CryptProtectData(ctypes.byref(in_blob), description, None, None, None, 1, ctypes.byref(out_blob)):
        err = ctypes.get_last_error()
        raise RuntimeError(f"CryptProtectData failed with error code: {err}")
    try:
        raw = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return "dpapi:" + base64.b64encode(raw).decode("ascii")
    finally:
        _LocalFree(out_blob.pbData)


def dpapi_unprotect_strict(cipher: str) -> ResolvedSecret:
    """Unprotect DPAPI cipher with typed outcome.
    
    Fail-loud: If decrypt fails, returns DPAPI_UNAVAILABLE. Never returns cipher text as key.
    """
    if not isinstance(cipher, str) or not cipher.strip():
        return ResolvedSecret(SecretStatus.EMPTY_SECRET, "")
    
    cipher = cipher.strip()
    if not cipher.startswith("dpapi:"):
        # Plaintext passthrough
        return ResolvedSecret(SecretStatus.SECRET_READY, cipher)
        
    if sys.platform != "win32" or _CryptUnprotectData is None:
        return ResolvedSecret(SecretStatus.DPAPI_UNAVAILABLE, "", "DPAPI not supported on this platform")

    try:
        raw = base64.b64decode(cipher[6:])
    except Exception as exc:
        return ResolvedSecret(SecretStatus.DPAPI_UNAVAILABLE, "", f"Base64 decode failed: {exc}")

    buf = ctypes.create_string_buffer(raw)
    in_blob = _DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = _DATA_BLOB()
    ctypes.set_last_error(0)
    # CRYPTPROTECT_UI_FORBIDDEN = 1
    if not _CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 1, ctypes.byref(out_blob)):
        err = ctypes.get_last_error()
        return ResolvedSecret(SecretStatus.DPAPI_UNAVAILABLE, "", f"CryptUnprotectData failed with error code: {err}")
    try:
        data = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        res_str = data.decode("utf-8")
        if res_str.startswith("dpapi:"):
            return ResolvedSecret(SecretStatus.DPAPI_UNAVAILABLE, "", "Decrypted payload returned another dpapi: envelope (corrupted payload)")
        return ResolvedSecret(SecretStatus.SECRET_READY, res_str)
    except Exception as exc:
        return ResolvedSecret(SecretStatus.DPAPI_UNAVAILABLE, "", f"UTF-8 decode failed: {exc}")
    finally:
        _LocalFree(out_blob.pbData)


def resolve_secret(secret_raw: str, env_dict: Optional[dict] = None) -> ResolvedSecret:
    """Resolve a raw secret string (which could be plaintext, env ref, or dpapi).
    
    Never expands recursively. Validates grammar and environment strictly.
    """
    if not isinstance(secret_raw, str) or not secret_raw.strip():
        return ResolvedSecret(SecretStatus.EMPTY_SECRET, "")

    text = secret_raw.strip()

    # 1. Check if DPAPI
    if text.startswith("dpapi:"):
        return dpapi_unprotect_strict(text)

    # 2. Check if Environment Reference
    m = ENV_REF_PATTERN.match(text)
    if m:
        var_name = m.group(1)
        lookup = env_dict if env_dict is not None else os.environ
        if var_name not in lookup:
            return ResolvedSecret(
                SecretStatus.MISSING_ENVIRONMENT_VARIABLE,
                "",
                f"Environment variable '{var_name}' is not set in process environment",
                env_var_name=var_name
            )
        val = lookup[var_name]
        if not val or not val.strip():
            return ResolvedSecret(
                SecretStatus.EMPTY_ENVIRONMENT_VARIABLE,
                "",
                f"Environment variable '{var_name}' is empty",
                env_var_name=var_name
            )
        resolved_val = val.strip()
        if resolved_val.startswith("dpapi:"):
            return ResolvedSecret(
                SecretStatus.INVALID_SECRET_REFERENCE,
                "",
                f"Environment variable '{var_name}' resolved to raw dpapi cipher, not allowed",
                env_var_name=var_name,
            )
        return ResolvedSecret(SecretStatus.SECRET_READY, resolved_val, env_var_name=var_name)

    # 3. Check for malformed syntax (e.g. contains ${ without full match, or leading $ or %)
    if "${" in text or re.search(r"^\$[A-Za-z_]|^\%[A-Za-z_]|Bearer\s+\$|Bearer\s+%", text):
        return ResolvedSecret(
            SecretStatus.INVALID_SECRET_REFERENCE,
            "",
            f"Malformed environment variable reference: '{text}'. Strict syntax requires entire string to be '${{NAME}}'",
        )

    # 4. Plaintext
    return ResolvedSecret(SecretStatus.SECRET_READY, text)
