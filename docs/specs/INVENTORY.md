# OpenViking Cockpit — Functional Feature Inventory & Parity Checklist

This document catalogs 100% of the functional capabilities, security invariants, and UI behaviors of the legacy Python Monitor (`openviking-monitor.pyw`) to serve as the strict parity baseline for the Rust/Tauri V2 rewrite.

---

## 1. Module Architecture & Source Breakdown (Measured at Commit `6333c22`)

| Module | Exact Lines | Primary Responsibilities |
| :--- | :--- | :--- |
| `monitor/openviking-monitor.pyw` | 5,343 | Main desktop application, lifecycle management, Tkinter UI event loop, background polling thread, slot modal editors, and top-level integration. |
| `monitor/watch_panel.py` | 563 | Independent bounded watchlist (max 7 credentials, `watch_keys.py:10`), per-row Auto, sequential background probing (20s / 64 token cap), auto-disable on consecutive 401/403, tray notification hooks, and action buttons. |
| `monitor/reserve_table.py` | 331 | Dedicated Reserve tab, treeview table for spare models, DPAPI-protected persistence, column width persistence, and action buttons. |
| `monitor/conf_gate.py` | 370 | Configuration validation gatekeeper, model name resolution, target classification, `allow_unaudited` failover slot bypass, and cache key generation. |
| `monitor/provider_security_auditor.py` | 3,216 | Behavioral security auditor (Taxonomy V3.1 probe suite), 3-tab modal presentation (Executive Summary, Inspector, Raw JSON), presentation sanitization, and 24h result caching. |
| `monitor/secret_store.py` | 220 | Native 64-bit Windows DPAPI bindings (`CryptProtectData`, `CryptUnprotectData`), fail-loud error handling, and strict environment variable grammar (`${VAR}`). |
| `monitor/safe_write.py` | 166 | Atomic file persistence (`os.replace`), interprocess locking (`msvcrt.locking`), and restrictive Windows DACL enforcement (SYSTEM, Administrators, Current User). |
| `monitor/openviking_monitor_notification.py` | 339 | Windows notification controller, rate limiting, deduplication, and tray balloon dispatch. |
| **Total Legacy Codebase** | **10,548** | Complete existing Python/Tkinter monitor codebase. |

---

## 2. Core Functional Capabilities & Parity Requirements

### Area 1: System Telemetry & Live Telemetry Dashboard
- **Server Health & Readiness:** Polls `/health` and `/ready` every second. Displays status indicator (Green/Yellow/Red) and reports active server version and auth mode.
- **Vector Database (VikingDB):** Reads `/api/v1/observer/vikingdb?format=json`. Displays vector count, vector dimension, backend type, and distance metric.
- **Long-term Memory (Memories):** Reads `/api/v1/stats/memories`. Displays total memory count, distribution by category (preferences, entities, events, etc.), hotness distribution (cold, warm, hot), and staleness metrics.
- **VLM Hot-Switch Telemetry:** Reads `/api/v1/observer/vlm/active`. Displays the currently active VLM slot index, total slot count `n`, manual hold status (`manual_hold`), and active credential identifiers.
- **Local Services:** Probes Ollama service (`127.0.0.1:21434`) and verifies embedding model availability.
- **Process & Port Guard:** Displays watchdog and port status.

### Area 2: Configuration & Slot Management (`ov.conf`)
- **Reading & Schema Parsing:** Loads `ov.conf` without expanding environment variables into raw memory to prevent write-back secret leakage.
- **Slot Hierarchy:** Supports Slot 0 (Primary) and Slots 1..N (Failover / Backup).
- **Slot Editor Modal:** Allows editing model name, Base URL, API key, and advanced parameters (temperature, timeout, max_tokens).
- **Model Combobox & Async Fetch:** Model input field supports both free-form typing and a dropdown list populated asynchronously via `list_chat_models`.
- **Pre-Write Backup & Atomic Replace:** Before any modification to `ov.conf`, creates a verified pre-write backup (`backups/ov.conf-before-...`), enforces restrictive DACL, performs interprocess locking, and atomically replaces the file.
- **Gatekeeper Policies:**
  - Slot 0 (Primary) strictly requires a valid passing security audit report.
  - Failover Slots (Slots 1..N) support `allow_unaudited=True`, prompting a 3-choice confirmation dialog (`Yes` = Audit now, `No` = Save without audit, `Cancel` = Abort) without forcing automated audit modals.
  - Grandfathering: Existing untouched slots are exempt from re-audit blocks.

### Area 3: THEO DÕI (Credential Watchlist)
- **Bounded Capacity:** Maximum 7 credential rows.
- **Probing Rules:**
  - Probes run sequentially with a 20-second timeout and a 64-output-token limit.
  - Exponential backoff upon repeated failures (capped at 60 minutes).
- **Auto-Disable & Notifications:**
  - Two consecutive HTTP 401 or 403 responses automatically disable that row's Auto switch.
  - Dispatches a native Windows Tray Balloon notification displaying alias and model (zero raw secrets in notifications).
- **Actions Bar:**
  - `+ Thêm key`: Opens editor modal.
  - `Lấy từ…`: Clones credential from Slot or Reserves independently.
  - `→ Dự trữ`: Copies credential to Reserves with duplicate fingerprint detection.
  - `Sửa`: Edits selected row.
  - `Thử ngay`: Immediate single probe.
  - `Kiểm định`: Directly launches the 3-tab Security Auditor modal for the selected key.
  - `Bật/tắt Auto`: Toggles Auto on selected row.
  - `Dừng`: Cancels in-flight batch.
  - `Xóa`: Deletes row from watchlist.

### Area 4: DỰ TRỮ (Spare Models Pool)
- **Independent Tab:** Full-width dedicated tab with search filter and status filtering.
- **Encrypted Storage:** Raw API keys are encrypted with Windows DPAPI on disk (`dpapi:...`) inside `monitor.json`.
- **Operational Actions:**
  - `Đưa vào slot`: Promotes reserve model to active slot in `ov.conf`.
  - `Thay slot lỗi`: Quickly swaps reserve model into a failing slot.
  - `Kiểm định an toàn`: Runs Taxonomy V3.1 security audit.
  - `Đưa sang Theo dõi`: Copies reserve model to Watchlist.
  - `Xóa key`: Deletes reserve model.

### Area 5: Security Auditor (Taxonomy V3.1)
- **3-Tab Layout:**
  - **Tab 1 (Kết luận & Hướng dẫn nhanh):** Executive summary with verdict level (Mức 1..5), status chips, and 3 concise operational guidance bullets (`✔ Dùng cho:`, `⚠ Cảnh báo / Tránh:`, `➤ Khuyến nghị:`).
  - **Tab 2 (Chi tiết Hạng mục):** Master-detail inspector table listing all test probes (Control chars, Prompt boundary, System override, etc.) with Vietnamese reason code mappings, latency, and full probe transcript.
  - **Tab 3 (Dữ liệu thô JSON):** Redacted raw JSON viewer with clipboard copy.
- **Caching:** Automatically checks 24-hour cached reports before re-running full network probes.
- **Sanitization:** Strict bearer token masking, length bounding (1 MiB cap), and control character stripping.

### Area 6: Windows Desktop & OS Integration
- **Single-Instance Mutex:** Global mutex `Global\OpenVikingMonitorMutex` ensures only one instance runs at a time; activating a duplicate raises the existing window.
- **Application User Model ID:** Sets `System.AppUserModel.ID` to ensure proper taskbar grouping and branding.
- **System Tray:** Native tray icon with minimize-to-tray, restore, open server log, and balloon notifications.
- **High-DPI Support:** Proper scaling factors (100%, 125%, 150%, 200%) with scrollable content views.
