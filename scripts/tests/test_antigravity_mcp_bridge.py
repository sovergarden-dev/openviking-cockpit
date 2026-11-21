"""Isolated unit and stdio protocol tests for the Antigravity OpenViking MCP bridge and plugin installer."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
BRIDGE_DIR = REPO_ROOT / "integrations" / "antigravity" / "openviking-memory" / "scripts"

sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(BRIDGE_DIR))

import install_antigravity_plugin
import ov_mcp_bridge


class _MockOpenVikingHandler(BaseHTTPRequestHandler):
    recorded_headers: list[dict[str, str]] = []

    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        _MockOpenVikingHandler.recorded_headers.append(
            {k.lower(): v for k, v in self.headers.items()}
        )
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "healthy": True, "version": "0.5.5"})
        elif self.path == "/api/v1/stats/memories":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "result": {
                        "total_memories": 12,
                        "by_category": {"preferences": 5, "entities": 7},
                        "hotness_distribution": {"warm": 4, "cold": 8, "hot": 0},
                    },
                },
            )
        elif self.path.startswith("/api/v1/observer/vikingdb"):
            self._send_json(
                200,
                {"status": "ok", "result": {"status": {"vector_count": 15, "dimension": 1024}}},
            )
        elif self.path.startswith("/api/v1/observer/queue"):
            self._send_json(
                200,
                {
                    "status": "ok",
                    "result": {
                        "status": {
                            "queues": [{"queue": "Embedding", "pending": 0, "in_progress": 0, "errors": 0}]
                        }
                    },
                },
            )
        elif self.path.startswith("/api/v1/content/read"):
            self._send_json(
                200,
                {
                    "status": "ok",
                    "result": "Rule note with leaked Bearer sk-testsecret1234567890 token",
                },
            )
        elif self.path.startswith("/api/v1/fs/ls"):
            self._send_json(
                200,
                {
                    "status": "ok",
                    "result": [
                        {"uri": "viking://user/default/memories/cases", "size": 0, "isDir": True}
                    ],
                },
            )
        else:
            self._send_json(404, {"status": "error"})

    def do_POST(self) -> None:
        _MockOpenVikingHandler.recorded_headers.append(
            {k.lower(): v for k, v in self.headers.items()}
        )
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8")
        body = json.loads(raw) if raw else {}

        if self.path == "/api/v1/search/find":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "result": {
                        "memories": [
                            {
                                "context_type": "memory",
                                "uri": "viking://user/default/memories/preferences/dpapi.md",
                                "level": 2,
                                "score": 0.9123,
                                "abstract": "Always store keys with Windows DPAPI",
                            }
                        ],
                        "resources": [],
                        "skills": [],
                        "total": 1,
                    },
                },
            )
        elif self.path == "/mcp":
            args = ((body.get("params") or {}).get("arguments") or {}).get("messages") or []
            first_text = args[0]["content"] if args else ""
            self._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": body.get("id", 1),
                    "result": {
                        "content": [{"type": "text", "text": f"Queued: {first_text}"}],
                        "isError": False,
                    },
                },
            )
        else:
            self._send_json(404, {"status": "error"})


class TestAntigravityMcpBridge(unittest.TestCase):
    def setUp(self) -> None:
        _MockOpenVikingHandler.recorded_headers.clear()
        self.httpd = HTTPServer(("127.0.0.1", 0), _MockOpenVikingHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)

    def test_rejects_non_loopback_base_url_by_default(self) -> None:
        with self.assertRaises(ValueError):
            ov_mcp_bridge.OpenVikingBridgeClient(base_url="https://evil.example.com")

    def test_stdio_jsonrpc_handshake_and_safe_tool_surface(self) -> None:
        import os

        bridge_script = BRIDGE_DIR / "ov_mcp_bridge.py"
        with tempfile.TemporaryDirectory() as tmp_ov_home:
            (Path(tmp_ov_home) / "ov.conf").write_text(
                '{"server":{"port":19330,"root_api_key":"${TEST_MCP_ROOT_KEY}"}}',
                encoding="utf-8",
            )
            merged_env = dict(os.environ)
            merged_env["OPENVIKING_BASE_URL"] = self.base_url
            merged_env["OPENVIKING_ACTOR_PEER"] = "antigravity"
            merged_env["OPENVIKING_OV_HOME"] = tmp_ov_home
            merged_env["TEST_MCP_ROOT_KEY"] = "SYNTHETIC_MCP_KEY_909"
            merged_env.pop("OPENVIKING_API_KEY", None)

            proc = subprocess.Popen(
                [sys.executable, "-X", "utf8", "-u", str(bridge_script)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                env=merged_env,
            )
            try:
                requests = [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "ov_recall", "arguments": {"query": "DPAPI"}},
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {
                            "name": "ov_read",
                            "arguments": {"uri": "viking://user/default/memories/preferences/dpapi.md"},
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {
                            "name": "ov_read",
                            "arguments": {"uri": "file:///C:/Windows/win.ini"},
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {
                            "name": "ov_remember",
                            "arguments": {"content": "Prefer Rust Tauri V2 cockpit", "category_hint": "preference"},
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/call",
                        "params": {
                            "name": "ov_list",
                            "arguments": {"uri": "viking://user/default/memories", "limit": 10},
                        },
                    },
                ]
                stdin_payload = "\ufeff" + "\n".join(json.dumps(r) for r in requests) + "\n"
                out, err = proc.communicate(input=stdin_payload, timeout=10)
                self.assertEqual(proc.returncode, 0, f"stderr={err}")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=3)

        responses = {json.loads(line)["id"]: json.loads(line) for line in out.splitlines() if line.strip()}
        self.assertEqual(responses[1]["result"]["serverInfo"]["name"], "openviking-memory")

        tool_names = [t["name"] for t in responses[2]["result"]["tools"]]
        self.assertEqual(
            tool_names,
            ["ov_recall", "ov_read", "ov_list", "ov_stats", "ov_remember"],
        )
        self.assertNotIn("forget", tool_names)
        self.assertNotIn("set_acl", tool_names)

        recall_data = json.loads(responses[3]["result"]["content"][0]["text"])
        self.assertEqual(recall_data["count"], 1)
        self.assertAlmostEqual(recall_data["hits"][0]["score"], 0.9123, places=4)

        # Verify bearer token sanitization on read
        read_data = json.loads(responses[4]["result"]["content"][0]["text"])
        self.assertIn("[REDACTED]", read_data["content"])
        self.assertNotIn("sk-testsecret1234567890", read_data["content"])

        # Verify non-viking:// URI is rejected with isError=True
        self.assertTrue(responses[5]["result"]["isError"])

        # Verify ov_remember sends X-OpenViking-Actor-Peer: antigravity and resolved root_api_key headers
        rem_data = json.loads(responses[6]["result"]["content"][0]["text"])
        self.assertTrue(rem_data["submitted"])
        self.assertEqual(rem_data["actor_peer"], "antigravity")
        self.assertTrue(
            any(
                h.get("x-openviking-actor-peer") == "antigravity"
                and h.get("x-api-key") == "SYNTHETIC_MCP_KEY_909"
                and h.get("authorization") == "Bearer SYNTHETIC_MCP_KEY_909"
                for h in _MockOpenVikingHandler.recorded_headers
            )
        )

        # Verify ov_list derives entry name from uri when OpenViking /fs/ls omits "name"
        list_data = json.loads(responses[7]["result"]["content"][0]["text"])
        self.assertEqual(list_data["count"], 1)
        self.assertEqual(list_data["entries"][0]["name"], "cases")
        self.assertTrue(list_data["entries"][0]["is_dir"])

    def test_plugin_installer_writes_atomic_bundle_and_mcp_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "plugins" / "openviking-memory"
            res = install_antigravity_plugin.install_plugin(
                target_dir=dest,
                python_exe=Path(sys.executable),
                ov_url="http://127.0.0.1:19330",
                actor_peer="antigravity",
                apply=True,
            )
            self.assertTrue(res["applied"])
            self.assertTrue((dest / "plugin.json").is_file())
            self.assertTrue((dest / "mcp_config.json").is_file())
            self.assertTrue((dest / "skills" / "openviking-memory" / "SKILL.md").is_file())
            self.assertTrue((dest / "rules" / "AGENTS.md").is_file())
            mcp_cfg = json.loads((dest / "mcp_config.json").read_text(encoding="utf-8"))
            srv = mcp_cfg["mcpServers"]["openviking-memory"]
            self.assertEqual(srv["env"]["OPENVIKING_ACTOR_PEER"], "antigravity")


if __name__ == "__main__":
    unittest.main()
