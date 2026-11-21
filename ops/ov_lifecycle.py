"""One-run lifecycle wrapper for the OpenViking watchdog.

Runs exactly one child (by default the installed `openviking-server` console
entry point, resolved read-only from the venv's installed metadata) and
appends sanitized lifecycle records to a JSONL file, so crashes are observable
without adding a supervisor.

Records carry metadata only -- run id, UTC timestamp, pids, monotonic uptime,
exit code (decimal + hex), and exception *type names*. Never command lines,
environment, or copies of server output: the lifecycle log must not risk
duplicating secrets, so raw output remains solely in server.log.

Invariants:
  * One run = one run id; every record is stamped with its own UTC time.
  * A child that never spawned yields `spawn-failed` + a non-zero exit code.
  * If the log cannot be opened before spawn, nothing is started (no
    untracked child). If a later write fails, the message goes to stderr and
    the child is left alone: no kill policy is invented here.
  * If this wrapper dies, the run's stop state simply stays unknown -- no
    clean exit is ever synthesized.

Usage: python -u -X faulthandler ov_lifecycle.py [--log PATH]
           (--entry-point NAME | -- CMD [ARG...])
Exit status: the child's own exit code.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG = Path.home() / ".openviking" / "logs" / "lifecycle.jsonl"
MAX_LOG_BYTES = 1_048_576
LOG_UNAVAILABLE_RC = 2
SPAWN_FAILED_RC = 127
HANG_KILLED_RC = 64
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
CREATE_NO_WINDOW = 0x08000000

CHILD_FLAGS = ["-u", "-X", "faulthandler"]


def format_exit_hex(code):
    return "0x%08X" % (code & 0xFFFFFFFF)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_run_id():
    return uuid.uuid4().hex


def record(log, payload):
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def observe(log, payload):
    """Write one record; a failure is reported once to stderr, never fatal."""
    try:
        record(log, payload)
        return True
    except OSError as exc:
        sys.stderr.write("ov_lifecycle: lifecycle observation failed (%s)\n"
                         % type(exc).__name__)
        sys.stderr.flush()
        return False


def rotate(log):
    try:
        if log.stat().st_size > MAX_LOG_BYTES:
            os.replace(log, log.with_name(log.name + ".old"))
    except OSError:
        pass


def resolve_entry_point(name):
    """Return "module:callable" for an installed console script (read-only)."""
    from importlib import metadata

    for entry_point in metadata.entry_points(group="console_scripts"):
        if entry_point.name == name:
            return entry_point.value
    raise LookupError(name)


def command_for_entry_point(value):
    """Build a python child that runs the entry point with our flags attached.

    The exe shim cannot receive `-u -X faulthandler`, so the child is this
    interpreter with the same flags; the target comes from installed metadata,
    never from a guessed `-m` module name.
    """
    module, _, attr = value.partition(":")
    bootstrap = (
        "import functools,importlib,sys;"
        "sys.exit(functools.reduce(getattr, %r, importlib.import_module(%r))())"
        % (attr.split("."), module)
    )
    return [sys.executable, *CHILD_FLAGS, "-c", bootstrap]


def validate_loopback_health_url(raw_url):
    """Accept only local loopback URLs for the health watchdog."""
    cleaned = (raw_url or "").strip()
    parsed = urllib.parse.urlparse(cleaned)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or host not in LOOPBACK_HOSTS:
        raise ValueError("health URL must target a local loopback host")
    return cleaned


def _probe_health_ok(opener, health_url):
    req = urllib.request.Request(health_url, method="GET")
    try:
        with opener.open(req, timeout=3.0) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _kill_hung_child_tree(child):
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW,
                timeout=10,
            )
        except Exception:
            pass
    try:
        if child.poll() is None:
            child.kill()
    except OSError:
        pass


def wait_with_health_monitor(
    child,
    log,
    base,
    started,
    health_url,
    grace_s,
    interval_s,
    max_failures,
    data_lock_path=None,
):
    """Wait on child normally or terminate a socket-hung process when loopback health fails repeatedly."""
    if not health_url:
        return child.wait()

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    poll_step = min(0.5, max(0.05, float(interval_s)))
    effective_interval = max(0.05, float(interval_s))
    effective_max = max(1, int(max_failures))
    ever_healthy = False
    consecutive_failures = 0
    last_probe = started

    while child.poll() is None:
        try:
            return child.wait(timeout=poll_step)
        except subprocess.TimeoutExpired:
            pass

        now = time.monotonic()
        if (now - last_probe) < effective_interval:
            continue
        if not ever_healthy and (now - started) < max(0.0, float(grace_s)):
            continue

        last_probe = now
        if _probe_health_ok(opener, health_url):
            ever_healthy = True
            consecutive_failures = 0
            continue

        consecutive_failures += 1
        if consecutive_failures >= effective_max and child.poll() is None:
            _kill_hung_child_tree(child)
            if data_lock_path:
                try:
                    Path(data_lock_path).unlink(missing_ok=True)
                except OSError:
                    pass
            observe(
                log,
                dict(
                    base,
                    utc=utc_now(),
                    event="hang-killed",
                    child_pid=child.pid,
                    consecutive_failures=consecutive_failures,
                    uptime_s=round(time.monotonic() - started, 3),
                ),
            )
            try:
                code = child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                code = HANG_KILLED_RC
            return code if code != 0 else HANG_KILLED_RC

    return child.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description="Record one OpenViking server run.")
    parser.add_argument("--log", default=str(DEFAULT_LOG))
    parser.add_argument("--entry-point", default=None,
                        help="installed console script to run (e.g. openviking-server)")
    parser.add_argument("--health-url", default=None,
                        help="optional loopback HTTP health URL to terminate a socket-hung server")
    parser.add_argument("--health-grace-s", type=float, default=90.0)
    parser.add_argument("--health-interval-s", type=float, default=15.0)
    parser.add_argument("--health-max-failures", type=int, default=3)
    parser.add_argument("--data-lock", default=None,
                        help="optional .openviking.lock path cleaned immediately after hang-kill")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.entry_point and command:
        parser.error("pass either --entry-point or an explicit command, not both")
    if not args.entry_point and not command:
        parser.error("missing --entry-point or child command after --")

    health_url = None
    if args.health_url:
        try:
            health_url = validate_loopback_health_url(args.health_url)
        except ValueError as exc:
            parser.error(str(exc))

    log = Path(args.log)
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        rotate(log)
        with open(log, "a", encoding="utf-8"):
            pass
    except OSError as exc:
        sys.stderr.write("ov_lifecycle: lifecycle log unavailable (%s); not starting child\n"
                         % type(exc).__name__)
        return LOG_UNAVAILABLE_RC

    base = {"run_id": new_run_id(), "wrapper_pid": os.getpid(), "parent_pid": os.getppid()}

    if args.entry_point:
        try:
            command = command_for_entry_point(resolve_entry_point(args.entry_point))
        except (LookupError, ValueError) as exc:
            observe(log, dict(base, utc=utc_now(), event="resolve-failed",
                              error_type=type(exc).__name__))
            sys.stderr.write("ov_lifecycle: entry point %r not installed\n" % args.entry_point)
            return SPAWN_FAILED_RC

    started = time.monotonic()
    # Inherits launcher stdout/stderr so server.log capture and 4MB rotation keep working untouched.
    try:
        child = subprocess.Popen(command)
    except OSError as exc:
        observe(log, dict(base, utc=utc_now(), event="spawn-failed",
                          error_type=type(exc).__name__))
        sys.stderr.write("ov_lifecycle: child spawn failed (%s)\n" % type(exc).__name__)
        return SPAWN_FAILED_RC

    observe(log, dict(base, utc=utc_now(), event="start", child_pid=child.pid))
    code = wait_with_health_monitor(
        child,
        log,
        base,
        started,
        health_url=health_url,
        grace_s=args.health_grace_s,
        interval_s=args.health_interval_s,
        max_failures=args.health_max_failures,
        data_lock_path=args.data_lock,
    )
    observe(log, dict(base, utc=utc_now(), event="exit", child_pid=child.pid,
                      exit_code=code, exit_code_hex=format_exit_hex(code),
                      uptime_s=round(time.monotonic() - started, 3)))
    return code


if __name__ == "__main__":
    sys.exit(main())
