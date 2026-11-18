# OpenViking Shared Memory Discipline

When the `openviking-memory` MCP tools (`ov_recall`, `ov_read`, `ov_list`, `ov_stats`, `ov_remember`) are available:

1. **Shared Read on Demand (`ov_recall` / `ov_read`)**:
   - Query `ov_recall` when the user references prior project decisions, personal preferences, local conventions, or cross-session context not already present in the current workspace.
   - Prefer filtering `target_uri` to `viking://user/default/memories/preferences`, `entities`, `patterns`, or `cases` first when looking for standing rules so historical `events` do not dilute top results.
   - Call `ov_read` only on the specific high-scoring URIs whose full body is needed.

2. **Curated Write Only (`ov_remember`)**:
   - Never dump raw conversation transcripts, routine command outputs, cron/batch progress ticks, or secrets/API keys into `ov_remember`.
   - Call `ov_remember` only when the user explicitly asks to remember something or when a durable cross-session fact (user preference, architectural invariant, or verified root-cause lesson) is established.
   - Writes automatically carry `X-OpenViking-Actor-Peer: antigravity` and land in `viking://user/default/peers/antigravity/memories/` without overwriting shared or other-agent memories.
