"""Lifecycle instrumentation tests for the OpenViking windowless launcher.

Covers ops/ov_lifecycle.py (one-run wrapper recording sanitized lifecycle
metadata) and the contract that ops/start-openviking-hidden.cmd invokes it
with `-u -X faulthandler` while preserving existing watchdog behavior.

Secret safety: records must carry metadata only -- never command lines,
environment, or duplicated log tails.

Every test spawns real (synthetic) child processes and cleans up only the
processes it created.
"""
import ast
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OPS = ROOT / "ops"
HELPER = OPS / "ov_lifecycle.py"
CMD = OPS / "start-openviking-hidden.cmd"
VENV_PY = Path.home() / ".openviking" / "venv" / "Scripts" / "python.exe"

CHILD_PID_THEN_EXIT = (
    "import os,sys;"
    "open(sys.argv[1],'w').write(str(os.getpid()));"
    "sys.exit(int(sys.argv[2]))"
)

CHILD_SLEEP_THEN_EXIT = (
    "import os,sys,time;"
    "open(sys.argv[1],'w').write(str(os.getpid()));"
    "print('hello-child', flush=True);"
    "time.sleep(float(sys.argv[2]));"
    "sys.exit(0)"
)

# Writes its pid, then waits argv[3] seconds before returning argv[2].
CHILD_SLOW_EXIT = (
    "import os,sys,time;"
    "open(sys.argv[1],'w').write(str(os.getpid()));"
    "time.sleep(float(sys.argv[3]));"
    "sys.exit(int(sys.argv[2]))"
)

FAKE_SERVER_MODULE = """
import faulthandler, os, sys


def main():
    with open(os.environ["FAKE_OV_OUT"], "w", encoding="utf-8") as handle:
        handle.write(str((sys.stdout.write_through, faulthandler.is_enabled(), sys.argv[1:])))
    return int(os.environ.get("FAKE_OV_RC", "0"))
"""


def taskkill(pid):
    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)


def pid_alive(pid):
    out = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid],
                         capture_output=True, text=True).stdout
    return str(pid) in out


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.dir = Path(self.tmp.name)
        self.log = self.dir / "lifecycle.jsonl"
        self.pidfile = self.dir / "child.pid"
        self.cleanup_pids = []
        if not HELPER.is_file():
            self.fail(f"Missing lifecycle helper {HELPER}")

    def tearDown(self):
        for pid in self.cleanup_pids:
            if pid_alive(pid):
                taskkill(pid)
        if self.log.is_file():
            os.chmod(self.log, stat.S_IWRITE | stat.S_IREAD)
        self.tmp.cleanup()

    def read_records(self):
        if not self.log.is_file():
            return []
        return [json.loads(line)
                for line in self.log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def wait_for(self, predicate, timeout=20.0, label="condition"):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.05)
        self.fail(f"timed out waiting for {label}")

    def read_pidfile(self):
        return int(self.pidfile.read_text(encoding="utf-8")) if self.pidfile.exists() else None

    def start_wrapper(self, *child_args):
        return subprocess.Popen(
            [sys.executable, "-u", str(HELPER), "--log", str(self.log), "--", *child_args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def run_helper(self, *child_args, expect=0, env=None):
        result = subprocess.run(
            [sys.executable, "-u", str(HELPER), "--log", str(self.log), "--", *child_args],
            capture_output=True, text=True, timeout=90, env=env,
        )
        self.assertEqual(result.returncode, expect, result.stderr)
        return result, self.read_records()

    def test_records_child_pid_and_watchdog_pid(self):
        _, records = self.run_helper(
            sys.executable, "-c", CHILD_PID_THEN_EXIT, str(self.pidfile), "0")
        real_pid = int(self.pidfile.read_text(encoding="utf-8"))
        start = [r for r in records if r["event"] == "start"]
        self.assertEqual(len(start), 1, records)
        self.assertEqual(start[0]["child_pid"], real_pid)
        self.assertGreater(start[0]["parent_pid"], 0, "watchdog parent PID must be recorded")
        self.assertNotEqual(start[0]["parent_pid"], real_pid)
        self.assertGreater(start[0]["wrapper_pid"], 0)
        self.assertEqual(len({r["run_id"] for r in records}), 1, "one run = one run_id")
        self.assertTrue(start[0]["run_id"])

    def test_records_exit_code_decimal_and_hex(self):
        _, records = self.run_helper(
            sys.executable, "-c", CHILD_PID_THEN_EXIT, str(self.pidfile), "7", expect=7)
        exit_rec = [r for r in records if r["event"] == "exit"]
        self.assertEqual(len(exit_rec), 1, records)
        self.assertEqual(exit_rec[0]["exit_code"], 7)
        self.assertEqual(exit_rec[0]["exit_code_hex"], "0x00000007")

    def test_hex_formatting_for_crash_codes(self):
        spec = importlib.util.spec_from_file_location("ov_lifecycle", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.format_exit_hex(0), "0x00000000")
        self.assertEqual(module.format_exit_hex(1), "0x00000001")
        self.assertEqual(module.format_exit_hex(-1073741819), "0xC0000005")

    def test_monotonic_uptime_and_per_record_utc(self):
        result, records = self.run_helper(
            sys.executable, "-c", CHILD_SLEEP_THEN_EXIT, str(self.pidfile), "0.6")
        self.assertIn("hello-child", result.stdout, "child stdout must pass through untouched")
        start = [r for r in records if r["event"] == "start"][0]
        exit_rec = [r for r in records if r["event"] == "exit"][0]
        self.assertGreaterEqual(exit_rec["uptime_s"], 0.5, exit_rec)
        self.assertLess(exit_rec["uptime_s"], 30, exit_rec)
        for record in records:
            self.assertRegex(record["utc"],
                             r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+\d{2}:\d{2}|Z)$")
        self.assertNotEqual(start["utc"], exit_rec["utc"],
                            "start and exit must be stamped per record, not copied")

    def test_run_id_differs_between_runs(self):
        self.run_helper(sys.executable, "-c", CHILD_PID_THEN_EXIT, str(self.pidfile), "0")
        first = {r["run_id"] for r in self.read_records()}
        self.run_helper(sys.executable, "-c", CHILD_PID_THEN_EXIT, str(self.pidfile), "0")
        records = self.read_records()
        self.assertEqual(len({r["run_id"] for r in records}), 2, records)
        self.assertEqual(len(first), 1)

    def test_spawn_failure_records_sanitized_event(self):
        missing = str(self.dir / "no-such-server.exe")
        result = subprocess.run(
            [sys.executable, "-u", str(HELPER), "--log", str(self.log), "--", missing],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0, "spawn failure must not report success")
        records = self.read_records()
        failed = [r for r in records if r["event"] == "spawn-failed"]
        self.assertEqual(len(failed), 1, records)
        self.assertEqual(failed[0]["error_type"], "FileNotFoundError")
        self.assertNotIn("exit", [r["event"] for r in records],
                         "no clean exit may be invented for a child that never ran")
        raw = self.log.read_text(encoding="utf-8")
        self.assertNotIn(missing, raw, "no command line in lifecycle log")
        for record in records:
            self.assertFalse({"cmdline", "argv", "env", "exception", "traceback"} & set(record),
                             f"forbidden field: {record}")

    def test_unwritable_log_prevents_spawn(self):
        blocked = self.dir / "blocked"
        blocked.mkdir()
        self.log = blocked  # a directory cannot be opened for append
        result = subprocess.run(
            [sys.executable, "-u", str(HELPER), "--log", str(self.log),
             "--", sys.executable, "-c", CHILD_PID_THEN_EXIT, str(self.pidfile), "0"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0, "unobservable run must not report success")
        self.assertIn("lifecycle log unavailable", result.stderr.lower())
        time.sleep(0.4)
        self.assertFalse(self.pidfile.exists(),
                         "child must not spawn when the log cannot be opened")

    def test_post_spawn_observation_failure_keeps_child_exit_code(self):
        proc = self.start_wrapper(
            sys.executable, "-c", CHILD_SLOW_EXIT, str(self.pidfile), "9", "4")
        child_pid = self.wait_for(self.read_pidfile, label="child pidfile")
        self.cleanup_pids.append(child_pid)
        self.wait_for(lambda: [r for r in self.read_records() if r["event"] == "start"],
                      label="start record")
        os.chmod(self.log, stat.S_IREAD)  # simulate a log that fails mid-run
        _, err = proc.communicate(timeout=90)
        self.assertEqual(proc.returncode, 9,
                         "child exit code must survive observation failure")
        self.assertIn("lifecycle observation failed", err.lower(),
                      "a lost observation must be visible, not silent")
        self.assertEqual([r["event"] for r in self.read_records()], ["start"],
                         "unwritable log keeps the records it already wrote")

    def test_killed_wrapper_leaves_stop_unknown(self):
        proc = self.start_wrapper(
            sys.executable, "-c", CHILD_SLOW_EXIT, str(self.pidfile), "0", "20")
        self.cleanup_pids.append(proc.pid)
        child_pid = self.wait_for(self.read_pidfile, label="child pidfile")
        self.cleanup_pids.append(child_pid)
        self.wait_for(lambda: [r for r in self.read_records() if r["event"] == "start"],
                      label="start record")
        taskkill(proc.pid)
        proc.wait(timeout=30)
        proc.stdout.close()
        proc.stderr.close()
        time.sleep(0.6)
        events = [r["event"] for r in self.read_records()]
        self.assertEqual(events, ["start"],
                         "wrapper death must leave the stop state unknown, never a clean exit")

    def test_killed_child_records_actual_nonzero_exit(self):
        proc = self.start_wrapper(
            sys.executable, "-c", CHILD_SLOW_EXIT, str(self.pidfile), "0", "20")
        self.cleanup_pids.append(proc.pid)
        try:
            child_pid = self.wait_for(self.read_pidfile, label="child pidfile")
            self.cleanup_pids.append(child_pid)
            self.wait_for(lambda: [r for r in self.read_records() if r["event"] == "start"],
                          label="start record")
            taskkill(child_pid)
            proc.communicate(timeout=30)
            records = self.read_records()
            self.assertEqual([r["event"] for r in records], ["start", "exit"])
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(records[1]["child_pid"], child_pid)
            self.assertEqual(records[1]["exit_code"], proc.returncode)
            self.assertEqual(records[1]["exit_code_hex"],
                             "0x%08X" % (proc.returncode & 0xFFFFFFFF))
            self.assertEqual(records[0]["run_id"], records[1]["run_id"])
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=30)

    def test_child_receives_python_flags_via_entry_point_metadata(self):
        site = self.dir / "site"
        (site / "fakeov").mkdir(parents=True)
        (site / "fakeov" / "__init__.py").write_text("", encoding="utf-8")
        (site / "fakeov" / "server.py").write_text(FAKE_SERVER_MODULE, encoding="utf-8")
        dist = site / "fakeov-1.0.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: fakeov\nVersion: 1.0\n", encoding="utf-8")
        (dist / "entry_points.txt").write_text(
            "[console_scripts]\nfake-server = fakeov.server:main\n", encoding="utf-8")
        out = self.dir / "flags.txt"
        env = {k: v for k, v in os.environ.items()
               if k not in {"PYTHONFAULTHANDLER", "PYTHONUNBUFFERED"}}
        env["PYTHONPATH"] = str(site)
        env["FAKE_OV_OUT"] = str(out)
        result = subprocess.run(
            [sys.executable, "-u", str(HELPER), "--log", str(self.log),
             "--entry-point", "fake-server"],
            capture_output=True, text=True, timeout=90, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(out.is_file(), "entry point from installed metadata must be invoked")
        write_through, fh_enabled, extra_argv = ast.literal_eval(out.read_text(encoding="utf-8"))
        self.assertTrue(write_through, "child must get -u (unbuffered stdout)")
        self.assertTrue(fh_enabled, "child must get -X faulthandler")
        self.assertEqual(extra_argv, [], "no extra argv may be injected")
        for record in self.read_records():
            self.assertNotIn("cmd", json.dumps(record))

    def test_missing_entry_point_is_recorded_and_not_spawned(self):
        result = subprocess.run(
            [sys.executable, "-u", str(HELPER), "--log", str(self.log),
             "--entry-point", "no-such-entry-point"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        events = [r["event"] for r in self.read_records()]
        self.assertEqual(events, ["resolve-failed"], events)

    @unittest.skipUnless(VENV_PY.is_file(), "OpenViking venv not installed")
    def test_real_venv_entry_point_resolves_from_installed_metadata(self):
        code = (
            "import importlib.util;"
            "spec=importlib.util.spec_from_file_location('ov_lifecycle', %r);"
            "m=importlib.util.module_from_spec(spec);"
            "spec.loader.exec_module(m);"
            "print(m.resolve_entry_point('openviking-server'))" % str(HELPER)
        )
        result = subprocess.run([str(VENV_PY), "-c", code],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "openviking_cli.server_bootstrap:main")

    def test_records_are_sanitized_metadata_only(self):
        secret = "«redacted:sk-…»"
        result, records = self.run_helper(
            sys.executable, "-c", CHILD_PID_THEN_EXIT, str(self.pidfile), "0", secret,
            expect=0)
        raw = self.log.read_text(encoding="utf-8")
        self.assertNotIn(secret, raw, "lifecycle log must never contain arguments/secrets")
        self.assertNotIn(CHILD_PID_THEN_EXIT, raw, "lifecycle log must never duplicate raw output")
        for record in records:
            self.assertFalse({"cmdline", "argv", "env", "log_tail", "stdout", "stderr"} & set(record),
                             f"forbidden field in lifecycle record: {record}")
        self.assertEqual(records[0]["event"], "start")

    def test_cmd_invokes_helper_unbuffered_with_faulthandler(self):
        content = CMD.read_text(encoding="utf-8")
        self.assertIn("ov_lifecycle.py", content)
        self.assertRegex(content, r"-u\s+-X\s+faulthandler",
                         "launcher must run helper with -u -X faulthandler")
        self.assertIn("--health-url", content,
                      "launcher must enable self-healing loopback health monitoring")
        self.assertIn("--entry-point openviking-server", content,
                      "child must be the installed server entry point, not the exe shim")
        self.assertNotIn("-m openviking", content, "no guessed -m module invocation")
        self.assertIn('set "OLLAMA_KEEP_ALIVE=30m"', content,
                      "embedding residency setting must survive")
        self.assertIn('set "RC=%ERRORLEVEL%"', content,
                      "child exit code must still drive restarts")
        self.assertIn("goto watchdog", content, "watchdog restart loop must survive")
        self.assertIn("ping -n 11", content, "10s crash-restart delay must survive")
        self.assertIn("4194304", content, "4MB log rotation must survive")

    def test_health_monitor_kills_hung_child_after_consecutive_failures(self):
        lock_file = self.dir / "synthetic.lock"
        lock_file.write_text("locked", encoding="utf-8")
        proc = subprocess.Popen(
            [
                sys.executable, "-u", str(HELPER),
                "--log", str(self.log),
                "--health-url", "http://127.0.0.1:19399/health",
                "--health-grace-s", "0.1",
                "--health-interval-s", "0.15",
                "--health-max-failures", "2",
                "--data-lock", str(lock_file),
                "--",
                sys.executable, "-c", CHILD_SLOW_EXIT, str(self.pidfile), "0", "30",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.cleanup_pids.append(proc.pid)
        child_pid = self.wait_for(self.read_pidfile, label="child pidfile")
        self.cleanup_pids.append(child_pid)
        proc.communicate(timeout=30)
        self.assertNotEqual(proc.returncode, 0, "hang-killed child must return non-zero")
        self.assertFalse(lock_file.exists(), "data-lock must be removed immediately after hang-kill")
        records = self.read_records()
        self.assertEqual([r["event"] for r in records], ["start", "hang-killed", "exit"], records)
        self.assertGreaterEqual(records[1]["consecutive_failures"], 2)
        raw = self.log.read_text(encoding="utf-8")
        self.assertNotIn("19399", raw, "lifecycle log must remain sanitized metadata only")
        for record in records:
            self.assertFalse({"cmdline", "argv", "env", "exception", "traceback", "stdout", "stderr", "url"} & set(record),
                             f"forbidden field in lifecycle record: {record}")

    def test_health_monitor_rejects_non_loopback_url(self):
        result = subprocess.run(
            [
                sys.executable, "-u", str(HELPER),
                "--log", str(self.log),
                "--health-url", "https://example.com/health",
                "--",
                sys.executable, "-c", CHILD_PID_THEN_EXIT, str(self.pidfile), "0",
            ],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.pidfile.exists(), "child must not spawn when health URL is non-loopback")


if __name__ == "__main__":
    unittest.main()
