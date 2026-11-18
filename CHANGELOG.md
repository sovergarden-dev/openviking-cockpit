# Changelog — OpenViking Cockpit

All notable changes to the OpenViking Cockpit, Monitor GUI, and Behavioral Security Auditor are documented in this file.

## [1.5.1] - 2026-11-18

### Changed
- Removed the unused `list_slots` Tauri IPC command and 3 unreferenced CSS custom properties (`--space-6`, `--text-base`, `--z-banner`), added an explicit `Ẩn khay` top-bar button for minimizing to the system tray, and synchronized `docs/specs/COCKPIT_RUST_SPEC.md` with the shipped crate layout.

### Fixed
- Made clicking the native Windows `✕` (`CloseRequested`) titlebar button cleanly tear down background workers, remove the system tray icon, and exit `openviking-cockpit.exe` instead of hiding the window into the background tray.
- Scoped Reserve concurrency checks to `reserves_sha256` (`compute_reserves_sha256` / `verify_reserves_sha` over `spare_models`) captured synchronously at click time in `cockpit_rs/ui/src/main.js`, preventing both shifted-index neighbor deletions during queued clicks and false `RevisionConflict` errors during background Watchlist Auto-probes, while surfacing top-bar alert toggle feedback across all tabs (`#topbar-status`).

## [1.5.0] - 2026-11-18

### Added
- Added instant NFC-normalized client-side Reserve filtering in `cockpit_rs/ui/` (`#reserve-filter-query`, `#reserve-filter-endpoint`, and `#reserve-filter-clear`) preserving backend `spare_models` indices across filtered views.
- Added top-bar tray alert switches (`notify_on_down`, `notify_on_failover`) and an inline Watchlist Auto-probe interval selector (`watch_auto_minutes`: `1` / `5` / `10` minutes) in `cockpit_rs`, wired through `MonitorStateSummary` and `set_watch_auto_state`.

### Changed
- Moved the `THEO DÕI` (`Watchlist`) panel in `cockpit_rs/ui/` into the `Tổng quan` (`Overview`) tab directly below the 5 status cards, converted the 3rd tab into a dedicated full-width `Dự trữ` (`Reserve`) view, and lowered the `cockpit_rs` watchlist capacity to `MAX_WATCHES = 4` (while preserving `LEGACY_MAX_WATCHES = 7` on load and shrink so legacy 5–7 key `monitor.json` files remain readable and deletable).
- Replaced invalid TOML syntax in `config/ov.conf.example` with OpenViking's actual JSON configuration schema using `${ENV_VAR}` credential placeholders, and aligned `config/monitor.json.example` with `watch_auto_enabled`, `watch_auto_minutes`, and `watch_keys`.

### Fixed
- Eliminated `monitor.json` Watchlist/Reserve deletion and toggle race conditions in `cockpit_rs` by serializing state writes behind `CockpitState::monitor_lock`, making `delete_watch_entry` idempotent against double-clicks, broadcasting `monitor://updated` after every IPC mutation and background `run_due_watch_auto_pass` probe, and adding a frontend FIFO mutation queue with immediate button disable states and compact tokenized table actions.
- Mapped `MonitorState::watch_interval_minutes` to `"watch_auto_minutes"` (with serde alias `"watch_interval_minutes"` and legacy `extra` key cleanup) so Rust and Python share the same persisted probe-interval field in `monitor.json`.

### Security
- Extended `is_live_path_protected()` in `cockpit_rs/src/config/safe_write.rs` to block unauthorized writes (`allow_live_write == false`) to `.openviking/monitor/monitor.json` in addition to `.openviking/ov.conf`.

## [1.4.0] - 2026-11-18

### Added
- Wired incident-debounced Windows tray balloon notifications (`notify_on_down` and `notify_on_failover` in `cockpit_rs`) for OpenViking port 19330 outages, missing Ollama embedding models (`qwen3-embedding:0.6b`), and automatic VLM backup slot failovers without false-alarming on manual operator holds, backed by `(mtime, size)` metadata caching, a tray-menu test action, and `--test-balloon` startup verification.
- Added one-click backend-side DPAPI Reserve promotion (`promote_reserve_to_slot`) with an inline target-slot selector on the Reserve card and duplicate-guarded Watchlist cloning (`copy_reserve_to_watch`) across distinct DPAPI salts in `cockpit_rs` so encrypted credentials move without exposing raw API keys across WebView IPC.
- Added sanitized child-process lifecycle instrumentation (`ops/ov_lifecycle.py` and `ops/start-openviking-hidden.cmd`) recording per-run PIDs, hex crash codes, and monotonic uptime to `logs/lifecycle.jsonl` while launching `openviking-server` with `-u -X faulthandler` and `OLLAMA_KEEP_ALIVE=30m`.
- Added digest-bound VLM slot quarantine (`monitor/slot_quarantine.py`) with finite evidence windows and manual-only recovery, alongside generation-fenced memory extraction write-health telemetry and alert routing in the Python monitor baseline (`84/84` isolated suites PASS).

### Security
- Added `docs/recovery-*/` and `monitor/_*.py` exclusion patterns to `.gitignore` to prevent accidental staging of local diagnostic artifacts containing workspace memory URIs.

## [1.3.0] - 2026-11-18

### Added
- Implemented the standalone Rust & Tauri V2 desktop host (`cockpit_rs/` and `cockpit_rs/src-tauri/`) alongside the legacy Python/Tkinter `monitor/` baseline, compiling to a portable Windows executable (`openviking-cockpit.exe`, ~8.5 MiB private working set idle) with single-instance Win32 mutex, `--tray` startup flag, duplicate-launch window restore, minimize-to-tray close handling, and native `Shell_NotifyIconW` tray balloon notifications on consecutive HTTP 401/403 watch auto-disable events.
- Implemented the active Taxonomy V3.1 Behavioral Security Auditor in Rust (`cockpit_rs/src/services/auditor.rs`, `auditor_cache.rs`) with monotonic `SecurityLatch`, 7 synthetic probes, chunk-bounded 64 KiB response reading, strict RFC 8259 duplicate-key and trailing-root JSON rejection, adaptive `PASS_SLOW` rescue ladder, byte-exact `_scope_id` cache interoperability with Python `provider_security_auditor.py`, and a tokenized 3-Tab Audit Modal UI (`cockpit_rs/ui/`).
- Built transactional `ov.conf` and `monitor.json` persistence in Rust (`cockpit_rs/src/config/safe_write.rs`, `conf_gate.rs`) with exclusive interprocess file locking, pre-write SHA-256 verified backups, restrictive Windows DACLs (`SYSTEM`, `Administrators`, Owner, Current User SID), `${ENV_VAR}` non-expansion guarantee, default live-path test protection with explicit desktop IPC write authorization, and Primary vs Failover (`allow_unaudited`) Slot Gatekeeper enforcement.
- Implemented native 64-bit Windows DPAPI (`dpapi:` envelope parity with Python `secret_store.py`), bounded Watchlist (`MAX_WATCHES = 7`, sequential 20s/64-token shared-client prober, 60m exponential backoff, 2x 401/403 auto-disable, corrupted-file preservation, SHA-256 revision conflict guard), Reserve pool CRUD with inline Edit/Cancel draft mode, and runtime VLM slot hot-switching (`/api/v1/observer/vlm/active`).
- Added THEO DÕI bounded credential watchlist (`watch_keys.py`, `watch_panel.py`, max 7 independent DPAPI credentials, global + per-row Auto switches, "Kiểm định" 3-tab audit action, "Đưa sang Theo dõi" transfer from Reserve, async `list_chat_models` Combobox refresh, and Windows tray balloon hook `notify_watch_auto_disabled`) and moved DỰ TRỮ into its own full-width tab.
- Added `docs/ops/recovery-runbook.md` and plan-first `scripts/retrofit_ov_conf_backup_acl.py` (`--apply`, `--plan-file`, `--receipt`) covering manual recovery of `monitor.json` and `ov.conf`, `.REJECTED[-N].json` triage, backup retention, and legacy backup DACL retrofitting.
- Bundled the blue sailboat icon artwork (`16–256` px) with `System.AppUserModel.ID` persistence across shortcuts, windows, and system tray.

### Changed
- Upgraded the Python security audit dialog (`build_audit_report_view()`) to a 3-tab layout (Executive Summary, Master-Detail Inspector with Vietnamese reason-code mappings, and redacted Raw JSON viewer), and allowed failover slots (`index >= 1`) to save conditionally with `allow_unaudited=True` while keeping primary slot 0 strictly gated.
- Reworked the Monitor UI palette, slot/editor hierarchy, three-round benchmark cancellation guards, and high-DPI geometry validation across Tk scaling `1.3333` (100%), `1.6667` (125%), `2.0` (150%), and `2.666667` (200% overview scroll).
- Made `suite_bootstrap.py` provision isolated per-suite home and `TMPDIR` profiles with live `.openviking` filesystem and network audit guards (`79/79` suites PASS).

### Fixed
- Preserved unreadable or corrupted `monitor.json` files fail-closed instead of overwriting with empty defaults, enforced SHA-256 state revision conflict guards across concurrent writers, and archived verified pre-change `monitor.json` snapshots under `backups/monitor-state/<sha256>/`.
- Locked shortcut generation in `monitor/openviking-monitor.pyw` via `is_live_installation()`, checked PowerShell exit status on Windows startup integration, and hardened `scripts/monitor_sync.py` to assert no live or repo Monitor instances run during staging/publishing.
- Guarded `on_auto_disabled` callback execution against `sys.stderr is None` under windowless `pythonw.exe` and prevented Watch edit-modal saves from re-enabling Auto after background auth failures.

### Security
- Hardened `backup_ov_conf()` to apply protected, restricted Windows DACLs (`SYSTEM`, `Administrators`, current Windows SID) on staging before writing `ov.conf` bytes, reject reparse points, verify `_conf_digest()` inside `.ov-writer.lock`, and quarantine drifted artifacts as `.REJECTED[-N].json`.
- Enforced fail-closed bearer/token masking, control-character stripping, 1 MiB `[OMITTED:LIMIT]` bounding in `_presentation_sanitize_text()`, key-hashed `model_cache_key` lookups, and strict rejection of unsafe URLs, HTTP redirects, and user-entered `dpapi:` envelopes.

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
