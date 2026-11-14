# OpenViking Server API Contracts & Schemas

This directory defines the structural API contracts between OpenViking Server and Cockpit clients (both legacy Python Monitor and the new Rust/Tauri Cockpit).

## Contract Baseline
- **Captured from:** OpenViking Server v0.5.3 (`auth_mode: dev`)
- **Transport:** HTTP REST JSON (`http://127.0.0.1:19330`)
- **Status:** All baseline endpoints verified healthy (`HTTP 200`).
- **Privacy & Sanitization:** All raw volatile counters, internal account hashes, and specific credential labels are sanitized into typed structural schemas.

## Schema Files
1. `health.schema.json`: Root health and version probe (`/health`).
2. `ready.schema.json`: Subsystem readiness checks (`/ready`).
3. `vlm_active.schema.json`: Runtime VLM active slot and manual hold state (`/api/v1/observer/vlm/active`).
4. `vikingdb.schema.json`: Local vector database telemetry (`/api/v1/observer/vikingdb?format=json`).
5. `memories_stats.schema.json`: Long-term memory repository metrics and category distribution (`/api/v1/stats/memories`).
