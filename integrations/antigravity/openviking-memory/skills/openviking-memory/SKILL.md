---
name: openviking-memory
description: How to search, read, and record durable long-term memories in the local OpenViking server (127.0.0.1:19330) using the safe 5-tool bridge (ov_recall, ov_read, ov_list, ov_stats, ov_remember). Use when recalling cross-session user preferences, project entities, architectural patterns, or persisting curated decisions without memory pollution.
---

# OpenViking Shared Memory (`openviking-memory`)

## Namespace Layout

| URI Prefix | Purpose |
| :--- | :--- |
| `viking://user/default/memories/preferences` | Standing user preferences, workflow habits, and constraints |
| `viking://user/default/memories/entities` | Projects, systems, services, and domain entities |
| `viking://user/default/memories/patterns` | Reusable engineering patterns and verified workflows |
| `viking://user/default/memories/cases` | Post-mortems and concrete bug-fix lessons |
| `viking://user/default/memories/events` | Chronological session milestones (noisy for broad rule lookups) |
| `viking://user/default/peers/antigravity/memories` | Peer-attributed memories recorded by Antigravity |
| `viking://user/default/peers/hermes/memories` | Peer-attributed memories recorded by Hermes |

## Workflow

1. **Lookup standing rules/context**:
   - Call `ov_recall` with a short, specific semantic query (`limit=5..8`, `context_type="memory"`).
   - Inspect returned `abstract` fields first (`L0/L1/L2`); call `ov_read` only on entries that directly answer the question.
2. **Persist durable knowledge**:
   - Distill the fact into 2–6 clear sentences (zero API keys, tokens, or ephemeral file diffs).
   - Call `ov_remember(content=..., category_hint="preference" | "entity" | "pattern" | "case")`.
3. **Safety boundary**:
   - Deletion (`forget`) and ACL mutation tools are intentionally omitted from this bridge so automated sessions cannot accidentally erase user memories.
