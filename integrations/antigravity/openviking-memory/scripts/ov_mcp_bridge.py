"""Stdlib-only MCP Stdio bridge exposing safe OpenViking memory tools to Antigravity.

Enforces three architectural guarantees by construction:
  1. Loopback-only target URL by default (`127.0.0.1`, `localhost`, `[::1]`).
  2. Read-broad (`ov_recall`, `ov_read`, `ov_list`, `ov_stats`) across shared and peer stores,
     paired with peer-attributed curated write (`ov_remember` -> `X-OpenViking-Actor-Peer: antigravity`).
  3. Impossible-by-shape deletion safety: `forget`, `set_acl`, and raw overwrite tools are never exposed.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from io import TextIOWrapper
from pathlib import Path

SERVER_NAME = "openviking-memory"
SERVER_VERSION = "1.10.2"
SUPPORTED_PROTOCOL_VERSIONS = {"2025-03-26", "2024-11-05"}
DEFAULT_PROTOCOL_VERSION = "2025-03-26"
MAX_READ_CHARS = 32_000
MAX_REMEMBER_CHARS = 16_000

SECRET_REDACT_RE = re.compile(
    r"""(?i)(\b(?:api[_-]?key|token|access_token|auth_token|secret|password)\b["']?\s*[=:]\s*|bearer\s+)(["']?)([^\s"']+)"""
)
ENV_PLACEHOLDER_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def resolve_ov_api_key(ov_home: Path | None = None) -> str:
    env_key = os.environ.get("OPENVIKING_API_KEY", "").strip()
    if env_key:
        return env_key
    home_override = os.environ.get("OPENVIKING_OV_HOME", "").strip()
    root = ov_home or (Path(home_override) if home_override else Path(os.environ.get("USERPROFILE") or Path.home()) / ".openviking")
    conf_path = root / "ov.conf"
    if not conf_path.is_file() or conf_path.is_symlink():
        return ""
    try:
        doc = json.loads(conf_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(doc, dict):
        return ""
    srv = doc.get("server")
    if not isinstance(srv, dict):
        return ""
    raw_key = srv.get("root_api_key")
    if not isinstance(raw_key, str) or not raw_key.strip():
        return ""
    val = raw_key.strip()
    if val.startswith("dpapi:"):
        return ""
    match = ENV_PLACEHOLDER_RE.match(val)
    if match:
        return os.environ.get(match.group(1), "").strip()
    return val


def sanitize_text(raw: str) -> str:
    if not raw:
        return ""
    cleaned_chars = []
    for ch in raw:
        code = ord(ch)
        is_ctrl = (code < 0x20 and ch not in ("\t", "\n", "\r")) or (0x7F <= code <= 0x9F)
        is_bidi = (0x202A <= code <= 0x202E) or (0x2066 <= code <= 0x2069)
        is_zw = (0x200B <= code <= 0x200D) or code == 0xFEFF
        if not (is_ctrl or is_bidi or is_zw):
            cleaned_chars.append(ch)
    text = "".join(cleaned_chars)
    return SECRET_REDACT_RE.sub(r"\1\2[REDACTED]", text)


def validate_base_url(raw_url: str) -> str:
    parsed = urllib.parse.urlparse(raw_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"Invalid OPENVIKING_BASE_URL: {raw_url!r}")
    host = parsed.hostname.lower()
    allow_remote = os.environ.get("OPENVIKING_ALLOW_REMOTE", "").strip() == "1"
    if not allow_remote and host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(
            f"Refusing non-loopback OPENVIKING_BASE_URL host {host!r} without OPENVIKING_ALLOW_REMOTE=1"
        )
    return raw_url.strip().rstrip("/")


def validate_viking_uri(uri: str) -> str:
    clean = (uri or "").strip()
    if not clean.startswith("viking://") or ".." in clean:
        raise ValueError("URI must start with 'viking://' and contain no '..' segments")
    return clean


class OpenVikingBridgeClient:
    def __init__(self, base_url: str | None = None, actor_peer: str | None = None, api_key: str | None = None):
        env_url = base_url or os.environ.get("OPENVIKING_BASE_URL", "http://127.0.0.1:19330")
        self.base_url = validate_base_url(env_url)
        raw_peer = (actor_peer or os.environ.get("OPENVIKING_ACTOR_PEER", "antigravity")).strip()
        self.actor_peer = re.sub(r"[^A-Za-z0-9._-]", "-", raw_peer)[:64] or "antigravity"
        raw_key = api_key if api_key is not None else resolve_ov_api_key()
        self.api_key = raw_key.strip()
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _headers(self, include_peer: bool = True) -> dict[str, str]:
        hdrs = {
            "Accept": "application/json",
            "User-Agent": f"OpenViking-Antigravity-MCP/{SERVER_VERSION}",
        }
        if self.api_key:
            hdrs["X-API-Key"] = self.api_key
            hdrs["Authorization"] = f"Bearer {self.api_key}"
        if include_peer and self.actor_peer:
            hdrs["X-OpenViking-Actor-Peer"] = self.actor_peer
        return hdrs

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        timeout: float = 12.0,
        extra_headers: dict[str, str] | None = None,
    ) -> dict:
        hdrs = self._headers(include_peer=True)
        if extra_headers:
            hdrs.update(extra_headers)
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base_url}{path}", data=body, headers=hdrs, method=method)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
                if raw.startswith("event:") or "\ndata:" in raw:
                    for ln in raw.splitlines():
                        if ln.startswith("data:"):
                            raw = ln[5:].strip()
                            break
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read(2048).decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            detail = sanitize_text(err_body)[:240]
            raise RuntimeError(f"OpenViking HTTP {exc.code}: {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenViking unreachable at {self.base_url}: {exc.reason}") from exc

    def recall(
        self,
        query: str,
        context_type: str | None = None,
        target_uri: str | None = None,
        limit: int = 8,
        min_score: float = 0.35,
    ) -> dict:
        clean_q = (query or "").strip()
        if not clean_q:
            raise ValueError("'query' must not be empty")
        capped_limit = max(1, min(int(limit), 25))
        body: dict = {"query": clean_q, "limit": capped_limit}
        if context_type and context_type.strip():
            ct = context_type.strip().lower()
            if ct not in ("memory", "resource", "skill"):
                raise ValueError("'context_type' must be one of: memory, resource, skill")
            body["context_type"] = ct
        if target_uri and target_uri.strip():
            body["target_uri"] = validate_viking_uri(target_uri)

        resp = self._request_json("POST", "/api/v1/search/find", payload=body, timeout=15.0)
        res = resp.get("result") or {}
        combined = []
        for bucket in ("memories", "resources", "skills"):
            for item in res.get(bucket) or []:
                score = item.get("score")
                if isinstance(score, (int, float)) and score < float(min_score):
                    continue
                combined.append(
                    {
                        "uri": sanitize_text(str(item.get("uri") or "")),
                        "context_type": sanitize_text(str(item.get("context_type") or bucket.rstrip("s"))),
                        "level": item.get("level"),
                        "score": round(float(score), 4) if isinstance(score, (int, float)) else None,
                        "abstract": sanitize_text(str(item.get("abstract") or "")),
                    }
                )
        combined.sort(key=lambda x: x["score"] if x["score"] is not None else -1.0, reverse=True)
        return {"query": clean_q, "count": len(combined[:capped_limit]), "hits": combined[:capped_limit]}

    def read(self, uri: str, max_chars: int = 8000) -> dict:
        clean_uri = validate_viking_uri(uri)
        capped = max(256, min(int(max_chars), MAX_READ_CHARS))
        q_uri = urllib.parse.quote(clean_uri, safe="")
        resp = self._request_json("GET", f"/api/v1/content/read?uri={q_uri}&limit={capped}", timeout=10.0)
        content = sanitize_text(str(resp.get("result") or ""))
        return {"uri": clean_uri, "content": content}

    def list_dir(self, uri: str = "viking://user/default/memories", limit: int = 50) -> dict:
        clean_uri = validate_viking_uri(uri)
        capped = max(1, min(int(limit), 200))
        q_uri = urllib.parse.quote(clean_uri, safe="")
        resp = self._request_json("GET", f"/api/v1/fs/ls?uri={q_uri}&limit={capped}", timeout=10.0)
        raw_res = resp.get("result")
        entries = []
        items = raw_res if isinstance(raw_res, list) else (raw_res.get("entries") or raw_res.get("items") or []) if isinstance(raw_res, dict) else []
        for entry in items[:capped]:
            if isinstance(entry, dict):
                raw_uri = str(entry.get("uri") or "").strip()
                raw_name = str(entry.get("name") or entry.get("path") or "").strip("/")
                if not raw_name and raw_uri.startswith("viking://"):
                    trimmed = raw_uri[len("viking://") :].strip("/")
                    raw_name = trimmed.rsplit("/", 1)[-1] if trimmed else ""
                if not raw_name:
                    continue
                entries.append(
                    {
                        "name": sanitize_text(raw_name),
                        "uri": sanitize_text(raw_uri),
                        "is_dir": bool(entry.get("isDir") or entry.get("is_dir")),
                    }
                )
            else:
                entries.append({"name": sanitize_text(str(entry))})
        return {"uri": clean_uri, "count": len(entries), "entries": entries}

    def stats(self) -> dict:
        health = self._request_json("GET", "/health", timeout=5.0)
        mem = self._request_json("GET", "/api/v1/stats/memories", timeout=8.0).get("result") or {}
        vdb = (
            (self._request_json("GET", "/api/v1/observer/vikingdb?format=json", timeout=8.0).get("result") or {})
            .get("status")
            or {}
        )
        queue_res = (
            (self._request_json("GET", "/api/v1/observer/queue?format=json", timeout=8.0).get("result") or {})
            .get("status")
            or {}
        )
        queues = queue_res.get("queues") or []
        return {
            "healthy": bool(health.get("healthy")),
            "version": health.get("version"),
            "actor_peer": self.actor_peer,
            "vector_count": vdb.get("vector_count"),
            "dimension": vdb.get("dimension"),
            "total_memories": mem.get("total_memories"),
            "by_category": mem.get("by_category"),
            "hotness_distribution": mem.get("hotness_distribution"),
            "queue_pending": sum(int(q.get("pending") or 0) for q in queues),
            "queue_in_progress": sum(int(q.get("in_progress") or 0) for q in queues),
            "queue_errors": sum(int(q.get("errors") or 0) for q in queues),
        }

    def remember(self, content: str, category_hint: str | None = None) -> dict:
        clean_content = (content or "").strip()
        if not clean_content:
            raise ValueError("'content' must not be empty")
        if len(clean_content) > MAX_REMEMBER_CHARS:
            raise ValueError(
                f"'content' exceeds {MAX_REMEMBER_CHARS} characters; distill the durable fact or decision first"
            )
        text = clean_content
        if category_hint and category_hint.strip():
            hint = re.sub(r"[^A-Za-z0-9_-]", "", category_hint.strip().lower())[:32]
            if hint:
                text = f"[{hint}] {clean_content}"

        rpc_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "remember",
                "arguments": {
                    "messages": [{"role": "user", "content": text}],
                },
            },
        }
        resp = self._request_json(
            "POST",
            "/mcp",
            payload=rpc_payload,
            timeout=20.0,
            extra_headers={"Accept": "application/json, text/event-stream"},
        )
        if "error" in resp and resp["error"]:
            raise RuntimeError(f"MCP remember error: {sanitize_text(str(resp['error']))}")
        result = resp.get("result") or {}
        blocks = result.get("content") or []
        summary_lines = [
            sanitize_text(str(b.get("text") or ""))
            for b in blocks
            if isinstance(b, dict) and b.get("text")
        ]
        if result.get("isError"):
            raise RuntimeError("; ".join(summary_lines) or "OpenViking remember returned isError=true")
        return {
            "submitted": True,
            "actor_peer": self.actor_peer,
            "detail": " ".join(summary_lines) or "Submitted for background memory extraction.",
        }


TOOLS_SPEC = [
    {
        "name": "ov_recall",
        "description": (
            "Search OpenViking shared long-term memory semantically (local embedding, read-only, zero LLM cost). "
            "Returns ranked URIs, scores, levels (L0/L1/L2), and abstracts across user/default and all peers."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Concise semantic search query describing the preference, project entity, pattern, or past decision.",
                },
                "context_type": {
                    "type": "string",
                    "enum": ["memory", "resource", "skill"],
                    "description": "Optional filter by context type (defaults to searching all types).",
                },
                "target_uri": {
                    "type": "string",
                    "description": "Optional viking:// scope prefix, e.g. 'viking://user/default/memories/preferences'.",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 25,
                    "default": 8,
                },
                "min_score": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.35,
                },
            },
            "required": ["query"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "ov_read",
        "description": "Read the full Markdown body of a specific OpenViking 'viking://' URI returned by ov_recall or ov_list.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uri": {
                    "type": "string",
                    "description": "Full viking:// URI to read (e.g. 'viking://user/default/memories/preferences/...').",
                },
                "max_chars": {
                    "type": "integer",
                    "minimum": 256,
                    "maximum": MAX_READ_CHARS,
                    "default": 8000,
                },
            },
            "required": ["uri"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "ov_list",
        "description": "List entries inside an OpenViking 'viking://' directory (read-only).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uri": {
                    "type": "string",
                    "default": "viking://user/default/memories",
                    "description": "Directory URI starting with 'viking://'.",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                },
            },
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "ov_stats",
        "description": "Inspect live OpenViking health, vector count, memory category/hotness counts, and extraction queue health.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "ov_remember",
        "description": (
            "Persist a curated, durable fact, user preference, project convention, or verified root-cause lesson into OpenViking "
            "under actor peer 'antigravity'. Never pass raw chat transcripts, temporary progress ticks, or secrets."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Concise, self-contained durable note to extract into long-term memory (no secrets).",
                },
                "category_hint": {
                    "type": "string",
                    "enum": ["preference", "entity", "pattern", "case"],
                    "description": "Optional semantic category hint.",
                },
            },
            "required": ["content"],
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
]


def handle_rpc_message(msg: dict, client: OpenVikingBridgeClient) -> dict | None:
    method = msg.get("method")
    req_id = msg.get("id")

    # JSON-RPC notifications have no "id" and expect no response.
    if req_id is None:
        return None

    if method == "initialize":
        params = msg.get("params") or {}
        requested_ver = str(params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION)
        negotiated = (
            requested_ver if requested_ver in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
        )
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_SPEC}}

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}

    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}}

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            if name == "ov_recall":
                data = client.recall(
                    query=args.get("query", ""),
                    context_type=args.get("context_type"),
                    target_uri=args.get("target_uri"),
                    limit=args.get("limit", 8),
                    min_score=args.get("min_score", 0.35),
                )
            elif name == "ov_read":
                data = client.read(
                    uri=args.get("uri", ""),
                    max_chars=args.get("max_chars", 8000),
                )
            elif name == "ov_list":
                data = client.list_dir(
                    uri=args.get("uri", "viking://user/default/memories"),
                    limit=args.get("limit", 50),
                )
            elif name == "ov_stats":
                data = client.stats()
            elif name == "ov_remember":
                data = client.remember(
                    content=args.get("content", ""),
                    category_hint=args.get("category_hint"),
                )
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {name!r}"},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}],
                    "isError": False,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": sanitize_text(str(exc))}],
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method!r}"},
    }


def serve_stdio(client: OpenVikingBridgeClient | None = None) -> int:
    bridge = client or OpenVikingBridgeClient()
    stdin = TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    stdout = TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)

    for raw_line in stdin:
        line = raw_line.lstrip("\ufeff").strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc.msg}"},
            }
            stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
            stdout.flush()
            continue

        if not isinstance(msg, dict):
            continue
        resp = handle_rpc_message(msg, bridge)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(serve_stdio())
