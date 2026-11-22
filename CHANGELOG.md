# Changelog — OpenViking Cockpit

All notable changes to the OpenViking Cockpit, Monitor GUI, and Behavioral Security Auditor are documented in this file.

## [Unreleased]

### Changed
- Consolidated `TelemetryClient` loopback HTTP builders into `build_loopback_client` so `Connection: close` is applied by default across all loopback endpoints (including VLM slot switch, semantic search, content read, and directory listing), and renamed `IncidentTracker::reset_server_down_streak` to `reset_outage_streaks` (`cockpit_rs/src/services/telemetry.rs`, `cockpit_rs/src-tauri/src/commands.rs`).

## [1.10.2] - 2026-11-22

### Fixed
- Added a 3-consecutive-tick (~6s) confirmation threshold (`SERVER_DOWN_CONSECUTIVE_FAILS`) to `IncidentTracker` for server-down and embedding-missing alerts, preventing single-tick transient disconnect warning balloons (`cockpit_rs/src/services/telemetry.rs`).
- Disabled loopback HTTP keep-alive pooling (`pool_max_idle_per_host(0)`) and attached `Connection: close` on telemetry probes in `TelemetryClient` to prevent Cockpit-side keep-alive connection-reset races against Windows `uvicorn`'s 5s idle timeout (`cockpit_rs/src/services/telemetry.rs`).
- Suppressed disconnect and embedding tray warnings while resetting failure streaks whenever `service_lock` is held during intentional Start/Restart operations (`cockpit_rs/src-tauri/src/commands.rs`).
- Removed unused `message` parameter from `setServiceButtonsBusy`, updated `#btn-server-start` visibility against `!backendServiceBusy` immediately after UI start/restart actions, cleared stale `selectedReserveIndices` on batch-delete errors, removed redundant DOM re-enable lines before `renderSlotsPanel()`, and shared `probingSlotIds` across `#btn-slots-probe-all` (`panels/overview.js`, `panels/reserve.js`, `panels/slots.js`).

## [1.10.1] - 2026-11-22

### Changed
- Added atomic batch reserve deletion command `delete_reserve_entries` (`cockpit_rs/src-tauri/src/commands.rs`, `lib.rs`, `cockpit_rs/src/services/watchlist.rs::remove_reserve_indices`) sharing single-transaction CAS SHA verification, backup, and DACL persistence with `delete_reserve_entry`.
- Replaced string-based busy matching in Tray restarts with typed `ServiceActionError` (`commands.rs`, `lib.rs`), emitted tray status messages via `service://restarted`, and raised the 6-column KPI grid breakpoint to `1600px` with wrapping `.c-actions` on the Server KPI card (`index.html`, `styles/app.css`).
- Updated `README.md` (`50 Rust + 13 Python CI`, `36` IPC commands), `docs/specs/COCKPIT_RUST_SPEC.md`, and corrected the `1.10.0` `CHANGELOG.md` Reserve membership badge description.

### Fixed
- Fixed `btn-reserve-delete-selected` reading `ev.currentTarget` after `await requestConfirm` (always `null`, leaving the button enabled) and snapshotted `reservesSha` before confirmation so batch deletion cannot double-submit or mutate shifted indices (`panels/reserve.js`).
- Fixed `#server-action-status` staying stuck on `"Đang thực thi…"` after System Tray restarts and prevented premature UI button re-enable during post-restart `refreshAll()` by tracking local vs backend busy states (`panels/overview.js`, `main.js`).
- Prevented `slow_telemetry_cache` from caching non-`Ok` (`Timeout`/`HttpError`) slow probes for 10s (`SlowTelemetryCache::all_ok` in `telemetry.rs`, `commands.rs`) and short-circuited slow telemetry calls when `/health` fails (`fetch_snapshot_tiered`).
- Fixed Log Viewer `Sao chép` copying stale lines when switching to missing or unreadable log files (`modals/log_viewer.js`, unifying alert classification via `classifyLogLine`), prevented duplicate concurrent 1-tap Slot probe clicks (`probingSlotIds` in `panels/slots.js`), synced Reserve membership badges inside `renderConfig` (`main.js`), and removed dead `createEmptyRow` import (`panels/overview.js`), dead `#watch-section` ID (`index.html`), and unused `TelemetryClient::fetch_snapshot_with_embedding` (`telemetry.rs`).

## [1.10.0] - 2026-11-22

### Added
- Tracked `total_hang_kills` (`hang-killed` events) from `logs/lifecycle.jsonl` in `LifecycleSummary` (`cockpit_rs/src/services/telemetry.rs`) and surfaced `Tự cứu treo` counters on the OpenViking Server KPI card when non-zero.
- Added Slot/Watch membership badges next to Reserve model names and guarded batch removal (`Xóa đã chọn`) in `cockpit_rs/ui/src/panels/reserve.js` using descending index commits with chained `reserves_sha256` verification.
- Added interactive segment breadcrumb navigation (`#memory-breadcrumb`) in `cockpit_rs/ui/src/panels/memory.js`, 1-tap clickable Slot status probe badges (`createProbeStatusBadge` in `utils/format.js`), and `Chỉ Lỗi / Cảnh báo` + `Sao chép` actions in `cockpit_rs/ui/src/modals/log_viewer.js`.

### Changed
- Merged `Tổng quan` and `Định tuyến Slot` into one unified 3-tab desktop workspace (`Tổng quan`, `Dự trữ`, `Bộ nhớ & Tra cứu`) in `cockpit_rs/ui/index.html`, `styles/app.css`, `main.js`, `panels/overview.js`, and `panels/slots.js` with a balanced `3x2` / `6x1` KPI grid, compact single-line `VLM Đang Phục Vụ` card, collapsible empty `THEO DÕI` hint, `c-btn--accent` secondary emphasis on Slot hot-switch buttons, and `Alt+1..3` keyboard shortcuts.
- Replaced flat 7-endpoint 2s polling with 2-tier polling (`TelemetryClient::fetch_snapshot_tiered` with `1500 ms` fast HTTP, `4000 ms` slow stats HTTP, and `10s` `slow_telemetry_cache` TTL in `CockpitState` refreshed immediately on manual `Làm mới` or service restart), eliminating spurious `LONG-TERM MEMORIES: Timeout` errors under high memory-store disk counts.
- Updated `docs/specs/COCKPIT_RUST_SPEC.md` and `README.md` to document the standalone Rust/Tauri V2 3-tab Cockpit layout and live behavior.

### Fixed
- Prevented queued duplicate restarts in `execute_service_action_and_wait` (`commands.rs`, `lib.rs`) by replacing `service_lock.lock().await` with non-queueing `try_lock()` and broadcasting `service://busy` via an RAII drop guard to disable UI service buttons synchronously during Tray restarts.
- Keyed `provider_tester.js` model checklist caching by `(key, normalizeEndpoint(apiBase))` and cleared stale loaded model IDs when switching or editing inline base URLs; included `refreshMemoryOverview()` status inside `refreshAll()` boolean return (`main.js`); removed redundant `onAuditClick` check (`format.js`) and unused `re`/`sys` imports (`test_launcher_contract.py`).

## [1.9.2] - 2026-11-21

### Changed
- Shared `execute_service_action_and_wait` readiness logic between Tauri command `control_openviking_service` and the System Tray `restart_server` menu action, emitting `service://restarted` after `/ready` synchronization so config drift and slot state update immediately upon tray restart.
- Removed the unused non-interactive `<span>` branch in `createAuditBadgeElement` (`cockpit_rs/ui/src/utils/format.js`) since all callers attach interactive audit handlers.
- Added dynamic column headers (`Loại` / `Tên mục` vs `Điểm` / `Tóm tắt`) and `↑ Thư mục cha` parent navigation in the read-only Memory Directory Explorer (`cockpit_rs/ui/src/panels/memory.js`, `cockpit_rs/ui/index.html`).

### Fixed
- Replaced forward-slash filesystem paths with Windows backslashes across `ops/start-openviking-hidden.cmd` so `cmd.exe` built-ins (`del /f /q` stale-lock cleanup and `move /y` 4MB log rotation) execute instead of failing silently under `>nul 2>&1`.
- Reaped the hung child process via `child.wait(timeout=10)` before retrying `data_lock_path` deletion (`_unlink_with_retry`), and removed unused `urllib.error` import in `ops/ov_lifecycle.py`.
- Stripped the `viking://` scheme prefix when deriving `VikingDirEntry::name` in `TelemetryClient::list_dir` (`telemetry.rs`) and `ov_mcp_bridge.py` (`list_dir`), skipping empty bare `"viking://"` root entries instead of returning `"viking:"`.
- Prevented unbounded recursive `AuditRequired` prompt loops across `drawer.js`, `reserve.js`, and `slots.js`, aligned `safeFallback` (`audit.js`) with `conf_gate.rs` `memory_permitted` rules for Level >= 4 slots, and captured `slotIndex` at submit time in `drawer.js`.
- Reset loaded `/v1/models` checklist state in `openProviderTester` (`provider_tester.js`) when opening with a different source key so models from a previous provider cannot leak into a new benchmark run.
- Cleared stale `#drift-banner` warnings when live `state.liveVlm.credential_ids` already matches `state.slots`, detected swapped-slot changes in `overview.js`, disabled `#btn-drift-apply-restart` while `state.serviceBusy`, disabled `#btn-watch-probe-all` when the Watch table is empty, and awaited `refreshAll()` before reporting `F5`/`Ctrl+R` refresh outcomes in `main.js`.

## [1.9.1] - 2026-11-21

### Fixed
- Derived `VikingDirEntry::name` in `cockpit_rs/src/services/telemetry.rs` and `name` in `integrations/antigravity/openviking-memory/scripts/ov_mcp_bridge.py` (`list_dir`) from the trailing segment of `uri` when OpenViking `0.5.5` `/api/v1/fs/ls` omits `"name"` and `"path"` fields, ensuring non-empty alphabetical labels in the Memory Directory Explorer and MCP `ov_list`.

## [1.9.0] - 2026-11-21

### Added
- Added self-healing loopback `/health` watchdog inside `ops/ov_lifecycle.py` (`--health-url`, `--health-grace-s`, `--health-interval-s`, `--health-max-failures`, `--data-lock`) wired through `ops/start-openviking-hidden.cmd` to terminate `WinError 64` socket-hung `openviking-server` process trees, clean `data-qwen06b/.openviking.lock`, and emit sanitized `hang-killed` lifecycle telemetry automatically even when the desktop UI is closed.
- Added guided V3.1 security audit resolution (`runGuidedSlotAuditWorkflow` with 3-choice confirmation in `components/confirm.js`) across `reserve.js`, `slots.js`, and `components/drawer.js` when a Slot mutation requires a V3.1 audit.
- Added read-only interactive Memory Directory Explorer (`TelemetryClient::list_dir`, Tauri IPC `list_viking_dir`, clickable Category & Peer rows, `cases`/`profile.md` scope options, dynamic peer scopes, and `Chép URI`/`Chép nội dung` actions in `panels/memory.js`).
- Added dynamic live-status System Tray tooltips (`format_tray_tooltip`) plus quick Tray menu actions (`Xem nhật ký Server (server.log)` via `tray://open-log` and `Khởi động lại OpenViking Server`) in `cockpit_rs/src-tauri/src/lib.rs`.
- Added 1-tap clickable `[M1..M5]` / `Chưa kiểm định` audit badges (`createAuditBadgeElement`) and double-click row editing (`dblclick`) across `Theo dõi`, `Định tuyến Slot`, and `Dự trữ` tables, a `Thử tất cả` toolbar action on `THEO DÕI`, interactive `Ollama` / `Extraction Queue` log jumps, `Slot #X` / `Dự trữ` / `Theo dõi` membership tags and `+ Lưu tất cả model OK vào Dự trữ` batch saving in `provider_tester.js`, and global `F5` / `Ctrl+R` / `Alt+1..4` keyboard shortcuts.

### Changed
- Localized Slot drift banner text to Vietnamese in `cockpit_rs/src/config/conf_gate.rs`, added live runtime drift detection against `state.liveVlm` in `cockpit_rs/ui/src/panels/slots.js`, and attached an inline `Áp dụng ngay (Khởi động lại Server)` button directly on `#drift-banner`.
- Added `scripts/tests/test_launcher_contract.py` and `scripts/tests/test_launcher_lifecycle.py` (including new loopback hang-kill and non-loopback rejection tests) to `.github/workflows/ci.yml` and updated `docs/specs/COCKPIT_RUST_SPEC.md` and `README.md` to 35 async IPC commands.

## [1.8.1] - 2026-11-21

### Changed
- Unified loopback endpoint checking across `conf_gate.rs`, `auditor_cache.rs`, `provider_probe.rs`, and `watchlist.rs` via `is_loopback_host()`, enforcing HTTPS on non-loopback slot endpoints.
- Extracted shared helpers for reserve table filtering (`getFilteredReserves` in `reserve.js`), failover audit cache lookups (`lookup_failover_cached_audit` in `commands.rs`), reserve probe fallback matching (`find_reserve_fallback_index`), and watch/reserve duplicate checks (`same_credential_tuple` / `sanitize_monitor_label` in `watchlist.rs`).
- Removed dead CSS tokens (`--shadow-md`, `--space-6`, `--z-sticky-bar`), redundant `[hidden]` selectors in `app.css`, unused `id="memory-search-badge"` in `index.html`, unused `state.js` properties and redundant JS `export` modifiers, orphaned `WATCH_MAX_TOKENS`, unused `BenchmarkProgressEvent::Failed`, unreferenced public Rust items, and the test-only `evaluate_telemetry_incidents()` wrapper.

### Fixed
- Keyed per-session slot connectivity badges (`state.slotProbes`) by stable `slot.id` instead of `slot_index` so slot swaps, promotions, and deletions preserve accurate probe badges on each row.
- Shifted selected indices in `state.selectedReserveIndices` when deleting an earlier Reserve row, updated `drawer.js` slot validation baseline when editing `#drawer-slot-index`, and refreshed remaining `+ Theo dõi` row buttons across open Provider Benchmark results when hitting the 4-key limit.
- Matched `raw_key` when resolving reserve probe fallback targets in `probe_reserve_entry` and `probe_reserves_batch` after concurrent Reserve list changes.

## [1.8.0] - 2026-11-21

### Added
- Added OpenAI-compatible provider model discovery (`GET /v1/models`) and cancellable single/multi-round (`1–5` rounds) latency benchmarking (`cockpit_rs/src/services/provider_probe.rs`, `list_provider_models`, `probe_credential`, `run_provider_benchmark`, `cancel_provider_benchmark`) running 100% inside Rust backend memory with zero secrets sent to WebView IPC, surfaced in a unified Provider Model Explorer & Benchmark modal (`cockpit_rs/ui/src/modals/provider_tester.js`).
- Added Reserve ping & bounded concurrency batch probing (`probe_reserve_entry`, `probe_reserves_batch` with `≤ 2` concurrent endpoints and per-endpoint serialization, plus `cancel_reserve_batch_probe`), slot connectivity probing, status/latency columns, status filters, multi-column sorting, and persistent backward-compatible `last_probe` tracking on `SpareModelRecord`.
- Added complete VLM Slot lifecycle operations in `conf_gate.rs` and `commands.rs`: reordering (`swap`), promoting to Primary (`promote_to_primary` with V3.1 gate verification), deleting fallback slots (`>= 1`), editing failback policy (`update_failback_policy` preserving UI `0 <-> 2147483647` sentinel semantics), and Rust-side `Slot -> Reserve` / `Slot -> Watch` cloning plus same-endpoint credential inheritance (`inherit_source`).
- Added a Slide-over Editor Drawer (`cockpit_rs/ui/src/components/drawer.js`) with inline `/v1/models` lookup and pre-save connectivity check, a `⚙ Cài đặt` header popover, a live Toast notification stack, viewport-clamped `⋯`/right-click context menus, a 2-step destructive Confirmation modal, a read-only Log Tail Viewer modal (`read_log_tail` over `server.log`, `ollama.log`, `lifecycle.jsonl`, `monitor_app.log`), and a read-only `Quét vệ sinh Lưu trữ (Dry-run)` card (`HygieneDryRunSummary`) in `Bộ nhớ & Tra cứu`.

### Changed
- Overhauled `cockpit_rs/ui/` layout and refactored `main.js` into native ES modules (`api.js`, `state.js`, `utils/`, `components/`, `modals/`, `panels/`) backed solely by `styles/tokens.css` variables: single-line non-wrapping Topbar with tab badges across `880px–1440px+`, unmistakably highlighted active/hold/failover VLM Slot rows synchronized live with telemetry, compact 1-line table density with sticky action toolbars, audit freshness/expiry indicators (`[M5 · age]` / `[Hết hạn]`), and full `Escape` / `Ctrl+K` keyboard support.
- Enforced fail-closed cross-endpoint guards inside `conf_gate.rs` and `watchlist.rs` rejecting Base URL changes without an explicit new or inherited matching-endpoint key, and scoped `compute_reserves_sha256` to structural reserve fields (`model`, `api_base`, `api_key`, `note`) so background probes never trigger false revision conflicts.
- Added a `75s` cold-boot startup grace window to `IncidentTracker` (`evaluate_telemetry_incidents_with_uptime` in `telemetry.rs`) suppressing transient server/embedding offline balloons until either `/ready` succeeds or `75s` elapse after app launch.
- Removed the six test-only `QueueStatus::total_*` and `TelemetrySnapshot::is_overall_healthy` exports in `cockpit_rs/src/services/telemetry.rs` so Rust library reachability aligns strictly with production callers.
- Extended `scripts/deploy_to_live.ps1` with `-SyncShortcuts` to cut Desktop, Start Menu, and Startup `OpenViking Monitor.lnk` shortcuts over to `openviking-cockpit.exe`, and documented the `AtLogon` Scheduled Task trigger in `docs/ops/windowless-startup.md`.
- Updated `docs/specs/COCKPIT_RUST_SPEC.md` and `README.md` to reflect the 34 async IPC commands, native ES module UI layout, and new provider, slot, log, and hygiene capabilities.

### Fixed
- Synced the `ov.conf` `(mtime, size)` poll cache synchronously at the start of `switch_active_slot`, `get_memory_overview`, `search_memories`, and `read_viking_content` in `cockpit_rs/src-tauri/src/commands.rs`, raised the `control_openviking_service` cold-boot readiness deadline from 35s to 75s to cover the 15s Ollama warm-up plus vector index load, and added a 250ms Windows handle-release wait before unlinking `.openviking.lock` after terminating hung processes on `ServiceAction::Start` in `cockpit_rs/src/services/service_control.rs`.
- Stripped leading UTF-8 BOM sequences per incoming JSON-RPC line in `serve_stdio` inside `integrations/antigravity/openviking-memory/scripts/ov_mcp_bridge.py` to prevent `-32700` parse errors from Windows pipe callers.

### Security
- Added `ov.conf` `server.root_api_key` fallback resolution (`resolve_ov_api_key`, supporting `${ENV_VAR}` placeholders while ignoring `dpapi:` ciphertext) and dual `X-API-Key` / `Bearer` header injection in `integrations/antigravity/openviking-memory/scripts/ov_mcp_bridge.py`.

## [1.7.1] - 2026-11-18

### Changed
- Removed the unreferenced `TelemetryClient::fetch_snapshot` wrapper in `cockpit_rs/src/services/telemetry.rs` and consolidated request authentication header attachment (`X-API-Key` and `Bearer`) into `TelemetryClient::attach_auth`.

### Fixed
- Extended `ServiceAction::Start` in `cockpit_rs/src/services/service_control.rs` to clear hung socket-dead `openviking-server` / `ov_lifecycle.py` processes and stale `data-*/.openviking.lock` files whenever TCP port `19330` has no active listener (`WinError 64` socket-hang self-healing on `Chạy Server`).
- Added monotonic request sequence guards (`memoryOverviewSeq`, `searchRequestSeq`, `previewRequestSeq`) across `refreshMemoryOverview`, `search_memories`, `openMemoryContentPreview`, and `#btn-close-memory-preview` in `cockpit_rs/ui/src/main.js` so out-of-order async IPC completions cannot overwrite newer results or reopen a closed preview card.

### Security
- Wired `server.root_api_key` resolution from `ov.conf` (`resolve_server_root_api_key` supporting `${ENV_VAR}` placeholders) into `CockpitState` initialization, `(mtime, size)` poll-cache reloads (`TelemetryClient::set_api_key`), and `scripts/ov_storage_hygiene.py` (`resolve_ov_api_key`).
- Added loopback-only URL boundary validation (`validate_ov_base_url` enforcing `127.0.0.1`, `localhost`, or `::1` unless `OPENVIKING_ALLOW_REMOTE=1`, with credential/query/fragment rejection) at the entry of `apply_hygiene_plan` in `scripts/ov_storage_hygiene.py` before any filesystem mutation.

## [1.7.0] - 2026-11-18

### Added
- Added guarded OpenViking service lifecycle controls (`control_openviking_service` for `start` and `restart` with 2-step UI confirmation, socket-hang orphan cleanup, `ov_stale_lock_clean.py` preflight, and `open_logs_folder`) plus a live `Extraction Queue` status card (`/api/v1/observer/queue?format=json`) on the `Tổng quan` tab in `cockpit_rs`.
- Added a read-only 4th tab `Bộ nhớ & Tra cứu` (`Memory & Vector Inspector`) in `cockpit_rs` (`get_memory_overview`, `search_memories`, `read_viking_content`), displaying Retrieval quality metrics, category/hotness distributions, per-peer namespace and disk storage footprints (`vectordb/`, `memories/`, `peers/`, `sessions/`, `backups/quarantine/`), and a live local-embedding semantic recall tester with sanitized content preview.
- Added the `openviking-memory` Antigravity plugin bundle (`integrations/antigravity/openviking-memory/` and `scripts/install_antigravity_plugin.py`) with a stdlib-only MCP Stdio bridge (`ov_mcp_bridge.py`) exposing 5 safe tools (`ov_recall`, `ov_read`, `ov_list`, `ov_stats`, `ov_remember` under `X-OpenViking-Actor-Peer: antigravity`) while omitting destructive `forget`/`set_acl` operations by construction.
- Added plan-first storage hygiene auditor `scripts/ov_storage_hygiene.py` (`--dry-run` default, SHA-256 `--plan-file` verification, protected `ov.conf` and `backups/pre-*` baselines, non-destructive `monitor-scratch` archiving, inactive `cron_*` session pruning, and synchronous `wait=true` API-backed `tick-events` pruning with milestone filename protection), along with isolated CI suites `test_antigravity_mcp_bridge.py` and `test_ov_storage_hygiene.py`.

### Changed
- Extended `scripts/deploy_to_live.ps1` with `-SyncAntigravityPlugin` for per-file atomic plugin synchronization alongside `openviking-cockpit.exe` and `ops/` deployment.

## [1.6.1] - 2026-11-18

### Changed
- Unified legacy backup ACL inspection in `scripts/retrofit_ov_conf_backup_acl.py` onto `monitor/safe_write.py` `inspect_file_acl()` (accepting Rust `OW` Owner Rights ACEs alongside `SY`/`BA`/CurrentUser without spawning `powershell.exe`), added `test_retrofit_ov_conf_backup_acl.py` to `.github/workflows/ci.yml`, and opted GitHub Actions JavaScript steps into Node 24 (`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`).

### Fixed
- Replaced the `powershell.exe` subprocess inside `monitor/safe_write.py` `apply_restricted_file_acl()` with direct 64-bit Win32 `advapi32` FFI (`SetNamedSecurityInfoW`, `GetNamedSecurityInfoW`, `GetSecurityDescriptorControl`, and `EqualSid`), eliminating PowerShell module-autoload failures under isolated `USERPROFILE` test sandboxes on `windows-latest` CI runners and speeding up ACL-verified writes by ~50x.
- Populated `cached_audit_level` on `ApplySlotOutcome.slots` returned directly by `apply_slot_update_with_live_policy` in `cockpit_rs/src/config/conf_gate.rs`.

### Security
- Made `safe_atomic_write_text()` in `monitor/safe_write.py` fail closed (`PermissionError`) when `apply_restricted_file_acl()` returns `False`, and routed `ov.conf-before-*` and `backups/monitor-state/<sha256>/monitor.json` snapshot creation in `cockpit_rs` through `write_restricted_bytes_atomic()` so restrictive Windows DACLs are applied on an empty staging file before any sensitive bytes touch disk.
- Enforced Taxonomy V3.1 decision-projection verification (`evaluate_v31_decision`) inside `load_cached_audit_verdict()` and `load_cached_audit_document()` in `cockpit_rs/src/services/auditor_cache.rs`, rejecting cached `audit_<scope_id>.json` files whose stored `verdict` fields disagree with `results`.

## [1.6.0] - 2026-11-18

### Added
- Added cached `[M1]..[M5]` Taxonomy V3.1 safety badges (`cached_audit_level`) across Slot, Watchlist, and Reserve tables in `cockpit_rs`, backed by 0ms cached report opening (`load_cached_audit_document` when `force_refresh` is false), an explicit `Đo lại (7 probe)` live rerun button (`#audit-modal-rerun`), and a `Sao chép JSON` button (`#audit-copy-json`) in the 3-Tab Audit Modal.
- Added bidirectional `Watch → Reserve` (`copy_watch_into_reserve` / `copy_watch_to_reserve` / `→ Dự trữ`) DPAPI credential cloning alongside `Reserve → Watch`, keeping encrypted secrets strictly inside Rust backend memory.
- Added `logs/lifecycle.jsonl` watchdog telemetry (`LifecycleSummary` via `(mtime, size)` poll cache) on the `OpenViking Server (19330)` card, added `ops/ov_stale_lock_clean.py` to version control, upgraded `scripts/deploy_to_live.ps1` (`-Target CockpitRs -Apply -SyncOps`) for atomic Rust binary + `ops/` live deployment, and added `.github/workflows/ci.yml` on `windows-latest`.
- Added top-bar `Khởi động cùng Windows` (`--tray`) Startup `.lnk` synchronization (bypassed under `COCKPIT_OV_HOME` test isolation) and multi-monitor-aware window geometry draft/restore persistence (`MonitorState::geometry`).

### Changed
- Capped `backups/monitor-state/<sha256>` snapshot retention in `cockpit_rs` (`MAX_MONITOR_STATE_BACKUPS = 30`) and extended `scripts/backup_retention.py` to protect `pre-*` baseline archives while quarantining stale `monitor-state/` directories non-destructively.

### Security
- Enforced restrictive Windows file DACLs (`apply_restricted_file_acl`) on `backups/monitor-state/<sha256>/monitor.json` snapshots written by `cockpit_rs`.

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
