"""Policy tests for the ov.conf mutation gate (validate_conf_targets).

Two admission standards:
  slot 0 (primary)      -> memory_permitted + no safety stop (unchanged, strict)
  slot >= 1 (failover)  -> additionally accepts level 3 "dùng tạm" WITH an
                           operator confirmation returned to the caller
Everything else raises: no report, expired report, safety_stop, level < 3.
"""
import ast
import sys
import types
from pathlib import Path

PYW = Path(__file__).resolve().parent.parent / "openviking-monitor.pyw"
tree = ast.parse(PYW.read_text(encoding="utf-8"))

WANTED = ("model_cache_key", "vlm_credentials_list", "effective_credentials",
          "credential_identity", "validate_conf_targets")
env = {}
ns = {}
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and node.name in WANTED:
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(PYW), "exec"), ns)
for name in WANTED:
    assert name in ns, f"missing {name} in openviking-monitor.pyw"

REPORTS = {}  # identity -> verdict dict


def _get_latest_audit_report(api_base, model, max_age_s=86400.0, *, api_key=None):
    return REPORTS.get((api_base, model, api_key))


stub = types.ModuleType("provider_security_auditor")
stub.get_latest_audit_report = _get_latest_audit_report
sys.modules["provider_security_auditor"] = stub
ns["validate_conf_targets"].__globals__.update(ns)

validate = ns["validate_conf_targets"]


def conf(slots):
    creds = [
        {"id": f"slot-{i}", "provider": "openai", "model": m, "api_base": b, "api_key": k}
        for i, (m, b, k) in enumerate(slots)
    ]
    vlm = {"model": creds[0]["model"], "api_base": creds[0]["api_base"], "api_key": creds[0]["api_key"],
           "credentials": creds}
    return {"vlm": vlm}


BASE = "https://api.example.com/v1"
PRIMARY = ("primary-model", BASE, "key-primary")


def verdict(level, permitted, stop=False, why=""):
    return {"verdict": {"verdict_level": level, "memory_permitted": permitted,
                        "safety_stop": stop, "why": why}}


def fresh():
    REPORTS.clear()


# 1. Unchanged primary, no new credentials -> no report required, no warnings.
fresh()
before = conf([PRIMARY])
out = validate(before, conf([PRIMARY]))
assert out == [], out
print("PASS unchanged primary needs no report")

# 2. New primary already memory-admitted -> silent pass.
fresh()
REPORTS[("https://new.example.com/v1", "new-primary", "key-new")] = verdict(4, True)
out = validate(conf([PRIMARY]), conf([("new-primary", "https://new.example.com/v1", "key-new")]))
assert out == [], out
print("PASS new admitted primary passes")

# 3. New primary at level 3 (memory not permitted) -> hard block.
fresh()
REPORTS[("https://new.example.com/v1", "weak-primary", "key-new")] = verdict(3, False, why="FAILED_QUALITY")
try:
    validate(conf([PRIMARY]), conf([("weak-primary", "https://new.example.com/v1", "key-new")]))
except ValueError as exc:
    assert "slot chính" in str(exc), exc
else:
    raise AssertionError("level-3 primary must be rejected")
print("PASS level-3 primary rejected")

# 4. New failover slot at level 3, no safety stop -> accepted with one advisory.
fresh()
poor = ("mistralai/mistral-large-2512", "https://api.xkiro.com/v1", "key-mistral")
REPORTS[(poor[1], poor[0], poor[2])] = verdict(3, False, why="FAILED_QUALITY")
out = validate(conf([PRIMARY]), conf([PRIMARY, poor]))
assert len(out) == 1 and out[0]["slot"] == 1 and out[0]["level"] == 3, out
assert out[0]["model"] == poor[0] and "FAILED_QUALITY" in out[0]["why"], out
print("PASS level-3 failover accepted as conditional")

# 5. New failover slot with safety stop -> hard block regardless of level.
fresh()
REPORTS[("https://bad.example.com/v1", "bad-model", "key-bad")] = verdict(1, False, stop=True,
                                                                         why="TIER0_VIOLATION")
try:
    validate(conf([PRIMARY]), conf([PRIMARY, ("bad-model", "https://bad.example.com/v1", "key-bad")]))
except ValueError as exc:
    assert "slot dự phòng 1" in str(exc), exc
else:
    raise AssertionError("safety_stop failover must be rejected")
print("PASS safety_stop failover rejected")

# 6. New failover slot with no report at all -> hard block (never silent).
fresh()
try:
    validate(conf([PRIMARY]), conf([PRIMARY, ("never-audited", BASE, "key-none")]))
except ValueError as exc:
    assert "slot dự phòng 1" in str(exc), exc
else:
    raise AssertionError("un-audited failover must be rejected")
print("PASS un-audited failover rejected")

# 7. Replacing a broken failover slot: the old backup identity is grandfathered
#    but the replacement still needs its own report (the dead-lock this fixes).
fresh()
REPORTS[(poor[1], poor[0], poor[2])] = verdict(3, False, why="FAILED_QUALITY")
broken = ("qwen/qwen3.8-omni-flash:free", "https://api.xkiro.com/v1", "key-qwen")
before = conf([PRIMARY, broken])
out = validate(before, conf([PRIMARY, poor]))
assert len(out) == 1 and out[0]["slot"] == 1, out
print("PASS broken failover replacement admitted conditionally")

# 8. Presenting an already-existing credential as a new slot stays grandfathered.
fresh()
before = conf([PRIMARY, poor])
out = validate(before, conf([PRIMARY, poor]))
assert out == [], out
print("PASS existing failover grandfathered")

print("CONF_TARGET_GATE_OK")
