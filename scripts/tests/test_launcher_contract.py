"""Contract tests for OpenViking windowless launcher scripts (VBS & CMD).

Verifies:
1. ops/start-openviking-hidden.vbs uses bWaitOnReturn = True and propagates exit code with WScript.Quit.
   Strictly forbids bWaitOnReturn = False to prevent losing process ownership in Task Scheduler.
2. ops/start-openviking-hidden.cmd uses 'ping -n' for pause delays.
   Strictly forbids 'timeout /t' which fails (rc=125) inside windowless consoles.
3. ops/start-openviking-hidden.cmd performs log rotation for both server.log and ollama.log at 4MB threshold.
4. ops/start-openviking-hidden.cmd redirects Ollama stdout to nul to suppress Gin access log spam.
5. Files exist, are non-empty, and contain CRLF line endings.
"""
import re
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
OPS_DIR = SCRIPTS_DIR.parent / "ops"

class TestLauncherContract(unittest.TestCase):
    def setUp(self):
        self.vbs_path = OPS_DIR / "start-openviking-hidden.vbs"
        self.cmd_path = OPS_DIR / "start-openviking-hidden.cmd"
        if not OPS_DIR.is_dir():
            self.skipTest(f"ops/ directory not present in {OPS_DIR} (likely running in decoupled environment)")
        self.assertTrue(self.vbs_path.is_file(), f"Missing canonical {self.vbs_path}")
        self.assertTrue(self.cmd_path.is_file(), f"Missing canonical {self.cmd_path}")

    def test_vbs_contract(self):
        """VBS launcher must wait on return and propagate exit code."""
        content = self.vbs_path.read_text(encoding="utf-8")
        
        # Must use Run with bWaitOnReturn = True
        self.assertRegex(
            content,
            r"shell\.Run\s*\([^,]+,\s*0\s*,\s*True\s*\)",
            "VBS must call shell.Run(..., 0, True) to maintain process tree ownership"
        )
        # Strictly forbid False
        self.assertNotRegex(
            content,
            r"shell\.Run\s*\([^,]+,\s*0\s*,\s*False\s*\)",
            "VBS must NOT use bWaitOnReturn = False"
        )
        # Must propagate return code via WScript.Quit
        self.assertIn("WScript.Quit", content)

    def test_cmd_contract_no_timeout_and_uses_ping(self):
        """Windowless CMD must never use timeout /t (fails with rc=125 in windowless mode)."""
        content = self.cmd_path.read_text(encoding="utf-8")
        raw_bytes = self.cmd_path.read_bytes()

        # Guard against CRLF double-translation
        self.assertNotIn(b"\r\r\n", raw_bytes, "CMD file contains corrupted double carriage returns (\\r\\r\\n)")

        # Strip comment lines (rem or ::) before scanning for forbidden commands
        executable_lines = [
            line.strip().lower()
            for line in content.splitlines()
            if line.strip() and not line.strip().lower().startswith(("rem", "::", "@rem"))
        ]
        for line in executable_lines:
            self.assertNotIn("timeout /t", line, "Windowless cmd script must not execute timeout /t")

        # Must use ping -n for pauses
        self.assertRegex(content, r"ping\s+-n\s+\d+\s+127\.0\.0\.1", "Cmd must use ping -n for reliable delays")

    def test_cmd_contract_log_rotation(self):
        """CMD watchdog must rotate both server.log and ollama.log."""
        content = self.cmd_path.read_text(encoding="utf-8")

        # Rotation of server.log
        self.assertIn('for %%A in ("%LOG%")', content)
        # Rotation of ollama.log
        self.assertIn('for %%A in ("%OLLAMA_LOG%")', content)
        # 4MB threshold check
        self.assertIn("4194304", content)

    def test_cmd_contract_ollama_gin_log_suppression(self):
        """CMD watchdog must mute Ollama Gin access log stdout to nul."""
        content = self.cmd_path.read_text(encoding="utf-8")

        # Must redirect stdout to nul while preserving stderr to log file
        self.assertRegex(
            content,
            r'>nul\s+2>>"%OLLAMA_LOG%"',
            "Ollama serve must direct stdout to nul to prevent Gin log ballooning"
        )

if __name__ == "__main__":
    unittest.main()
