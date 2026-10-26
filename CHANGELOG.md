# Changelog — OpenViking Cockpit

All notable changes to the OpenViking Cockpit, Monitor GUI, and Behavioral Security Auditor are documented in this file.

## [v1.2.0-hardening] — 2026-10-26

### Security Hardening & Secret Isolation (Notion AI Sy06 & Sy01 Audited)
- **Native 64-bit Windows DPAPI (`monitor/secret_store.py`)**:
  - Replaced inline ctypes bindings with dedicated `secret_store` module using `WinDLL("crypt32", use_last_error=True)` and `WinDLL("kernel32", use_last_error=True)`.
  - Added strict `argtypes` and `restype` signatures for `CryptProtectData`, `CryptUnprotectData`, and `LocalFree`.
  - Fixed pointer truncation and premature buffer garbage collection by retaining explicit buffer handles during unprotect calls.
  - Implemented **Fail-Loud** error policy: Decryption errors return typed `DPAPI_UNAVAILABLE` status; ciphertext is strictly forbidden from being returned as usable key.
  - Strict environment variable grammar: `^\${[A-Za-z_][A-Za-z0-9_]*}\$`. Categorized statuses: `SECRET_READY`, `MISSING_ENVIRONMENT_VARIABLE`, `EMPTY_ENVIRONMENT_VARIABLE`, `INVALID_SECRET_REFERENCE`.

- **Atomic File Persistence & DACL Enforcement (`monitor/safe_write.py`)**:
  - Implemented atomic safe file replacement (`os.replace`) using unique destination-directory temp files (`.tmp`).
  - Added interprocess file locking via `msvcrt.locking` on Windows to prevent lost updates from concurrent processes.
  - Enforced restrictive DACLs (`SYSTEM:(F)`, `Administrators:(F)`, current user `(F)`) on temp files before writing sensitive bytes, with post-replace DACL re-verification.
  - Hardened parent directories `C:\Users\rurus\.openviking`, `monitor/`, and `backups/` by stripping inherited `CodexSandboxUsers` ACEs.

- **Elimination of Secret Write-Back Leakage**:
  - Split configuration read paths into `read_ov_conf_raw()` (preserves raw strings) and `read_ov_conf()`.
  - Completely removed `os.path.expandvars` from Monitor config loading, preventing resolved environment secrets in memory from being serialized back to `ov.conf`.
  - Enforced invariant in `write_ov_conf()`: Reject any payload containing `dpapi:` encrypted blobs to ensure server compatibility.
  - Preflight Gating: `probe_model()` verifies secret resolution before making HTTP calls, blocking network traffic on unresolved environment variables or DPAPI errors.

- **Gatekeeper Grandfathering & Self-Healing**:
  - Fixed slot-vs-top shadowing lockout in `validate_conf_targets()` by grandfathering the top-level `vlm.model` in addition to existing slot credentials.
  - Restored live `ov.conf` Slot 0 to canonical `gemini-3.8-flash-high`.
  - Hermetically isolated unit test harnesses (`test_writeback_invariants.py`) using isolated temporary `USERPROFILE` environments to prevent test sentinels from touching live configurations.

- **Test Runner Expansion & Independent Verification**:
  - Expanded test runner to **41 suites (100% PASS)**: Added `test_secret_store.py`, `test_safe_write.py`, `test_writeback_invariants.py`, and integrated `scripts/tests/test_deploy_safety.py` and `test_runner_safety.py`.
  - Persisted independent adversarial review receipts from Notion AI workspaces Sy06 (`docs/reviews/notion-20261026/`) and Sy01 (`docs/reviews/notion-20261026-next-steps/`).

---

## [v1.1.0] — 2026-10-25

### Core Stabilization & Taxonomy V3.1
- Standardized provider decision levels via `_project_decision()` in `provider_security_auditor.py`.
- Enforced single-source truth for Level 1–5 verdicts matching Taxonomy V3.1 specifications.
- Created `scripts/monitor_sync.py` and safety tests for transactional dry-run deployment.
