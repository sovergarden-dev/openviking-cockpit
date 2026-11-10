"""Contracts for the Monitor inline-audit recovery path."""
from __future__ import annotations

import ast
from pathlib import Path

MONITOR_DIR = Path(__file__).resolve().parent.parent
MONITOR = MONITOR_DIR / "openviking-monitor.pyw"
AUDITOR = MONITOR_DIR / "provider_security_auditor.py"
monitor_source = MONITOR.read_text(encoding="utf-8")
auditor_source = AUDITOR.read_text(encoding="utf-8")
monitor_tree = ast.parse(monitor_source)
auditor_tree = ast.parse(auditor_source)
monitor_functions = [node for node in ast.walk(monitor_tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
auditor_functions = [node for node in ast.walk(auditor_tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]

start_inline = next((node for node in monitor_functions if node.name == "start_inline_audit"), None)
assert start_inline is not None, "missing asynchronous inline-audit dispatcher"
start_inline_src = ast.get_source_segment(monitor_source, start_inline) or ""
assert "launch_security_audit_ui" in start_inline_src
assert "on_complete" in start_inline_src
assert "on_failure" in start_inline_src

assert "finish_action=finish_action" in start_inline_src

apply_edit = next((node for node in monitor_functions if node.name == "apply_conf_edit"), None)
assert apply_edit is not None
apply_src = ast.get_source_segment(monitor_source, apply_edit) or ""
assert "except AuditRequired" in apply_src
assert "start_inline_audit" in apply_src
assert "allow_inline_audit" in apply_src
assert "expected_digest" in apply_src

launch_ui = next((node for node in auditor_functions if node.name == "launch_security_audit_ui"), None)
assert launch_ui is not None
params = {arg.arg for arg in launch_ui.args.args + launch_ui.args.kwonlyargs}
assert {"on_failure", "close_on_complete"}.issubset(params), "audit failures must not silently leave a pending save"

print("INLINE_AUDIT_CONTRACT_OK")
