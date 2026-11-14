# OpenViking Cockpit (Rust/Tauri V2) — Technical Architecture Specification

This specification defines the complete architectural blueprint for rewriting the OpenViking Cockpit from Python/Tkinter into **Rust and Tauri V2**.

---

## 1. Executive Summary & Goals

### 1.1 Objectives
1. **Zero Runtime Dependencies:** Produce a single, compact, standalone portable executable (`openviking-cockpit.exe`) that runs directly on Windows without requiring a Python interpreter, virtual environment, or external package managers.
2. **Minimal Resource Footprint:** Target **<30 MB RAM idle** (compared to ~120 MB in Python Tkinter) and near-zero CPU usage when polling.
3. **Rock-Solid Stability & Concurrency:** Eliminate UI freezes and single-thread bottlenecks by leveraging Rust's `tokio` multi-threaded async runtime for background probing, telemetry streaming, and security audits.
4. **100% Strict Parity:** Maintain exact behavioral, cryptographic, and operational parity with the 10,548 lines of legacy Python code cataloged in `INVENTORY.md`.

---

## 2. Technology Stack

| Layer | Component | Version / Specification | Justification |
| :--- | :--- | :--- | :--- |
| **Desktop Host** | **Tauri V2** | `tauri = "2.0"` | Uses native Windows WebView2; lightweight, secure IPC, built-in system tray and window state management. |
| **Core Runtime** | **Rust** | `2021 Edition` (`rustc 1.97+`) | Memory safety, zero-cost abstractions, deterministic performance. |
| **Async Engine** | **Tokio** | `tokio = { version = "1.40", features = ["full"] }` | High-throughput asynchronous task scheduling for polling and probe queues. |
| **HTTP Client** | **Reqwest** | `reqwest = { version = "0.12", features = ["json", "rustls-tls"] }` | Fast, asynchronous HTTP/REST client with explicit connection pooling and timeouts. |
| **Windows OS API** | **Windows Crate** | `windows = { version = "0.58", features = ["Win32_Security_Cryptography", "Win32_Foundation", "Win32_System_SystemServices", "Win32_UI_WindowsAndMessaging", "Win32_Security_Authorization"] }` | Direct native access to Windows DPAPI (`CryptProtectData`), Mutex, DACL manipulation, and Tray Balloon APIs without ctypes overhead. |
| **Serialization** | **Serde** | `serde = { version = "1.0", features = ["derive"] }`, `serde_json = "1.0"` | Zero-copy JSON serialization matching `docs/specs/contracts/` schemas. |
| **Frontend UI** | **Webview** | HTML5 / CSS / TypeScript / Tailwind | Modern dark-themed dashboard, responsive high-DPI scaling, and real-time SVG charts. |

---

## 3. Repository Structure (`cockpit_rs/`)

The rewrite lives in an isolated workspace directory `cockpit_rs/` inside `G:/AI/openviking-cockpit/`, leaving the legacy `monitor/` tree 100% untouched:

```text
G:/AI/openviking-cockpit/
├── monitor/                     # Legacy Python/Tkinter code (untouched, active live baseline)
├── docs/specs/                  # Specifications, parity inventory, and contract schemas
│   ├── INVENTORY.md
│   ├── COCKPIT_RUST_SPEC.md
│   └── contracts/
│       ├── health.schema.json
│       ├── ready.schema.json
│       ├── vlm_active.schema.json
│       ├── vikingdb.schema.json
│       └── memories_stats.schema.json
└── cockpit_rs/                  # NEW Rust / Tauri V2 Project
    ├── Cargo.toml               # Cargo workspace / project definition
    ├── src-tauri/
    │   ├── Cargo.toml           # Tauri backend dependencies
    │   ├── tauri.conf.json      # Tauri V2 configuration (app identity, tray, permissions)
    │   └── src/
    │       ├── main.rs          # Process entry point, single-instance mutex, and Tauri bootstrap
    │       ├── lib.rs           # Core library and IPC registration
    │       ├── core/            # Cryptographic & Storage Foundation
    │       │   ├── dpapi.rs         # Native 64-bit Windows DPAPI encryption
    │       │   ├── safe_write.rs    # Atomic file persistence & DACL hardening
    │       │   ├── config_gate.rs   # ov.conf parser, slot validator, and failover policy
    │       │   └── secret_store.rs  # Strict ${ENV} secret resolver & fail-loud status
    │       ├── services/        # Asynchronous Background Services
    │       │   ├── telemetry.rs     # 1-second server polling (health, ready, stats)
    │       │   ├── watchlist.rs     # Sequential watch prober (20s/64t, auto-disable)
    │       │   ├── auditor.rs       # Taxonomy V3.1 probe suite & 24h caching
    │       │   └── backup.rs        # ov.conf & monitor.json snapshot retention
    │       ├── tray.rs          # Native system tray & balloon notification dispatcher
    │       └── commands/        # Tauri IPC Commands
    │           ├── telemetry_cmd.rs
    │           ├── config_cmd.rs
    │           ├── watch_cmd.rs
    │           ├── spare_cmd.rs
    │           └── audit_cmd.rs
    └── ui/                      # Modern Web Dashboard Frontend
        ├── package.json
        ├── index.html
        ├── src/
        │   ├── main.ts
        │   ├── components/      # Overview, WatchPanel, ReserveTable, AuditModal, SlotEditor
        │   └── styles/          # Dark Theme palette & high-DPI responsive layouts
        └── dist/
```

---

## 4. Architectural Invariants & Security Guarantees

### 4.1 Native Windows DPAPI v2 Compatibility
- **Format Parity:** Ciphertext stored on disk in `monitor.json` must continue using the `dpapi:<base64>` envelope to allow bidirectional interoperability with the legacy Python application if needed.
- **Fail-Loud Guarantee:** If DPAPI decryption fails (e.g. data transferred across machines or different Windows user profile), the key is flagged as `_dpapi_locked: true` and raw ciphertext is **never** emitted as an API key.

### 4.2 Transactional File Persistence & Restrictive DACLs
- **Target Files:** `ov.conf` and `monitor/monitor.json`.
- **Pre-Write Backup:** Any write to `ov.conf` must first create a timestamped backup (`ov.conf-before-...`).
- **DACL Enforcement:** Before sensitive bytes are committed, permissions on the temporary staging file (`.tmp`) must be stripped of inherited rights and restricted exclusively to:
  - `NT AUTHORITY\SYSTEM` (Full Control)
  - `BUILTIN\Administrators` (Full Control)
  - Current User SID (Full Control)
- **Atomic Swap:** File replacement is executed via Win32 `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` and `MOVEFILE_WRITE_THROUGH`.

### 4.3 Background Watch Probing & Auto-Disable Lifecycle
- **Sequential Execution:** Watchlist probes execute sequentially (one key at a time) via a dedicated Tokio worker task to avoid saturating network or rate limits.
- **Strict Caps:** 20.0-second network timeout, 64 output tokens maximum per probe.
- **Auto-Disable & Balloon Notification:**
  - Upon receiving **2 consecutive HTTP 401 or 403** responses, that row's `auto_enabled` is set to `false` and `auto_disabled_reason` is populated.
  - The tray manager dispatches a native balloon notification displaying only `alias` and `model` (no credentials or tokens).

### 4.4 Slot Gatekeeping & Failover Policy
- **Primary Slot 0:** Strictly blocked from committing changes unless a valid, fresh passing audit report exists.
- **Failover Slots 1..N:** Support `allow_unaudited=True`, permitting the user to save unaudited backup models with an advisory warning without forcing an automated modal popup.

---

## 5. Phased Implementation Plan

| Phase | Description | Deliverables | Verification Gates |
| :---: | :--- | :--- | :--- |
| **Phase 1** *(Current)* | **Specification & Contracts** | `INVENTORY.md`, `COCKPIT_RUST_SPEC.md`, JSON Schemas, Synthetic Fixtures. | All schemas validated against live server responses; zero secret leaks. |
| **Phase 2** | **Project Scaffolding & Core Foundation** | Initialize `cockpit_rs/`, build native `dpapi.rs`, `safe_write.rs`, and IPC command skeletons. | Rust unit tests for DPAPI roundtrip, atomic write DACL checks, and config parsing. |
| **Phase 3** | **Telemetry & Read-Only Dashboard** | Tokio telemetry service polling `/health`, `/ready`, `/vlm/active`, `/vikingdb`, and `/stats/memories`; modern Webview dashboard. | Side-by-side verification: telemetry readouts in Rust Cockpit match legacy Python Monitor byte-for-byte. |
| **Phase 4** | **Watchlist, Reserves & Auditor** | Sequential probe worker, DPAPI reserve management, Taxonomy V3.1 audit engine, and Tray balloon notifications. | Automated test suite verifying 2x 401 auto-disable, 24h audit caching, and failover slot save rules. |
| **Phase 5** | **Golden Testing & Cutover Readiness** | Golden regression suite comparing Rust binary vs Python scripts; packaged standalone `.exe`. | 100% parity pass on all 79 test concepts; ready for synchronized deployment with OpenViking 0.5.5. |
