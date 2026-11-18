# OpenViking Shared Memory Plugin for Antigravity

Connects Antigravity to your local OpenViking server (`http://127.0.0.1:19330`) through a zero-dependency Python 3.11 stdlib MCP bridge.

## Tools Provided

- `ov_recall` — Fast semantic search across `user/default` and `peers/*` using local Ollama embeddings (`qwen3-embedding:0.6b`).
- `ov_read` — Read full Markdown content of any `viking://` URI.
- `ov_list` — Browse `viking://` directories.
- `ov_stats` — Check live server health, vector counts, memory categories, and extraction queue status.
- `ov_remember` — Submit curated durable notes attributed to `X-OpenViking-Actor-Peer: antigravity`.

Destructive tools (`forget`, `set_acl`, `cancel_watch`) are excluded by construction.
