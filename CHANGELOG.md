# Changelog — OpenViking Cockpit

All notable changes to the OpenViking Cockpit, Monitor GUI, and Behavioral Security Auditor are documented in this file.

## [Unreleased]

### Separate Reserve Tab and Independent Key Watchlist
- Moved DỰ TRỮ into its own full-width tab. Its controls use two rows and keep manual probes/audits; the previous slot Auto loop is removed.
- Added THEO DÕI to Tổng quan: at most 7 independent credentials, no search, global Auto switch plus per-row Auto. Both default off; migration does not reuse the old Auto setting.
- Added DPAPI-protected watch persistence, strict endpoint/key validation, stable IDs/revisions and stale-response rejection. Watch edits, probes and imports never apply slots or write `ov.conf`.
- Sequential watch probes use 20-second timeouts and a 64-output-token budget. Backoff caps at 60 minutes; two consecutive 401/403 responses disable that row's Auto.
- Provider response bodies and raw exception messages are excluded from saved probe failures. Authenticated requests reject unsafe URLs and redirects.
- Strengthened high-DPI geometry assertions to require 3 fully visible watch rows, not merely a nonempty partial-row bounding box, and scrolling to row 7.
- Added `watch_keys.py` and `watch_panel.py` to the transactional source deployment manifest.
- Fixed the edit-modal race that could re-enable Auto after background auth failures; editor saves merge only current user fields against the latest record.
- Rejected user-entered `dpapi:` envelopes. Null watch lists normalize to empty; malformed nonempty watch data disables Auto and state writes, shows a warning, and preserves original bytes instead of silently discarding credentials.

### Watch Transfer and Reliability
- Added **Đưa sang Theo dõi** to the Reserve context menu and action row. It opens a prefilled, masked editor; Save makes an independent DPAPI watch with Auto off and keeps the reserve unchanged. Missing/locked keys, ambiguous selections and capacity overflow do not copy or probe.
- Made settings saves transactional: persistence succeeds before shared state and Windows startup/tray/window effects change. Failures remain inline without Tk tracebacks.
- Double-clicking the Auto cell toggles once and does not open Edit. Row Auto waiting on the master switch reads **Chờ tổng**; manual-only auth failures no longer claim an Auto shutdown.
- Watch modal validation is inline, the source picker owns a modal grab and both dialogs use the existing dark-titlebar helper.
- Old results display **Cũ** after the greater of 10 minutes or two configured intervals. This is a presentation warning, not a credential/provider verdict.
- Added seven-record DPAPI save/reopen/restore tests, failed atomic-save preservation and synthetic network/timeout/429/locked-key tests.
- Extended layout validation to Tk scaling 2.666667 (Windows 200% font factor). At high DPI, the overview scrolls vertically and minimum width scales within screen bounds; the slot editor reduces its scrollable model-list height to keep actions reachable.

### Test Isolation
- Made `suite_bootstrap.py` create its own per-suite scratch profile before executing test code, including standalone invocations outside the full runner.
- Added a subprocess sentinel regression that proves writes stay in the isolated profile and leave the caller's Monitor state untouched.
- Added a filesystem audit guard against live `.openviking` access, including direct absolute paths.
- Drained pending Tk theme events before destroying the note-field test root to avoid callbacks targeting a destroyed interpreter.

### Monitor UI Recovery & DPI Validation — 2026-11-11
- Reworked the Monitor palette, slot/editor hierarchy, reserve table sizing, audit result styling, and modal dark titlebars.
- Restored the three-round benchmark action alongside protocol verification and security audit controls.
- Kept probe failures visibly failed regardless of a prior provider audit level.
- Guarded benchmark completion/failure events after Escape or dialog closure.
- Scaling validation uses Tk's Windows DPI factors: **1.3333 (100%)**, **1.6667 (125%)**, and **2.0 (150%)**, with four live and four spare fixture rows plus seven watch rows, populated queue/vector/usage/retrieval telemetry, long endpoints, and failed-probe details.
- Dashboard regression checks run at 880×560, 996×960, 1020×640, and 880/1100/1400×800. Startup fit grows a default 1020×640 window to the measured overview content height within screen bounds; hidden reserve content cannot inflate its bounds.
- Reduced MODEL control padding, wrapped model names and retained complete role labels at high DPI. Long reserve cells have per-column fit checks and a tested horizontal scrollbar.
- Reserve-table column-width persistence survives hiding/showing the note column and restarting the table.
- Added four-slot split-boundary and minimum-window event-loop regression coverage.
- Added regression coverage for benchmark modal cancellation, stale completion events, add/edit/spare geometry, and high-DPI endpoint fit.

### Scaling Limits

- Startup sizing cannot exceed the usable screen height (screen height minus 120 px); when the measured content is taller, vertical controls require scrolling or a taller display.
- High-DPI content uses an outer overview scrollbar above 150%; it is not forced into one 960px-tall view. A low-resolution display can still require a smaller desktop scale.
- Benchmark cancellation stops queued probes but does not interrupt a currently executing HTTP request; timeout bounds remain the in-flight stop limit.

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
