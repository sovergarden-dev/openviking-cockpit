"""Policy tests for the ov.conf mutation gate (validate_conf_targets).

Two admission standards:
  slot 0 (primary)      -> memory_permitted + no safety stop (strict, 24h TTL)
  slot >= 1 (failover)  -> accepts level 3 "dùng tạm" WITH operator confirmation (7-day TTL)
Everything else raises: no report, expired report, safety_stop, level < 3.
"""
from __future__ import annotations

from pathlib import Path
import sys
import types
import unittest

MONITOR_DIR = Path(__file__).resolve().parent.parent
if str(MONITOR_DIR) not in sys.path:
    sys.path.insert(0, str(MONITOR_DIR))

# Create stub module for provider_security_auditor
REPORTS = {}  # identity -> report dict


def _get_latest_audit_report(api_base, model, max_age_s=86400.0, *, api_key=None):
    report = REPORTS.get((api_base, model, api_key))
    if not report:
        return None
    return report


stub = types.ModuleType("provider_security_auditor")
stub.get_latest_audit_report = _get_latest_audit_report
sys.modules["provider_security_auditor"] = stub

import conf_gate  # noqa: E402
from conf_gate import AuditRequired, compute_conf_drift, validate_conf_targets  # noqa: E402


def conf(slots):
    creds = [
        {"id": f"slot-{i}", "provider": "openai", "model": m, "api_base": b, "api_key": k}
        for i, (m, b, k) in enumerate(slots)
    ]
    vlm = {
        "model": creds[0]["model"],
        "api_base": creds[0]["api_base"],
        "api_key": creds[0]["api_key"],
        "credentials": creds,
    }
    return {"vlm": vlm}


BASE = "https://api.example.com/v1"
PRIMARY = ("primary-model", BASE, "key-primary")


def verdict(level, permitted, stop=False, why="", age_s=0.0):
    return {
        "report_age_s": age_s,
        "verdict": {
            "verdict_level": level,
            "memory_permitted": permitted,
            "safety_stop": stop,
            "why": why,
        },
    }


def fresh():
    REPORTS.clear()


# 1. Unchanged primary, no new credentials -> no report required, no warnings.
fresh()
before = conf([PRIMARY])
out = validate_conf_targets(before, conf([PRIMARY]))
assert out == [], out
print("PASS unchanged primary needs no report")

# 2. New primary already memory-admitted -> silent pass.
fresh()
REPORTS[("https://new.example.com/v1", "new-primary", "key-new")] = verdict(4, True)
out = validate_conf_targets(conf([PRIMARY]), conf([("new-primary", "https://new.example.com/v1", "key-new")]))
assert out == [], out
print("PASS new admitted primary passes")

# 3. New primary at level 3 (memory not permitted) -> hard block.
fresh()
REPORTS[("https://new.example.com/v1", "weak-primary", "key-new")] = verdict(3, False, why="FAILED_QUALITY")
try:
    validate_conf_targets(conf([PRIMARY]), conf([("weak-primary", "https://new.example.com/v1", "key-new")]))
except ValueError as exc:
    assert "slot chính" in str(exc), exc
else:
    raise AssertionError("level-3 primary must be rejected")
print("PASS level-3 primary rejected")

# 4. New failover slot at level 3, no safety stop -> accepted with one advisory.
fresh()
poor = ("mistralai/mistral-large-2512", "https://api.xkiro.com/v1", "key-mistral")
REPORTS[(poor[1], poor[0], poor[2])] = verdict(3, False, why="FAILED_QUALITY")
out = validate_conf_targets(conf([PRIMARY]), conf([PRIMARY, poor]))
assert len(out) == 1 and out[0]["slot"] == 1 and out[0]["level"] == 3, out
assert out[0]["model"] == poor[0] and "FAILED_QUALITY" in out[0]["why"], out
print("PASS level-3 failover accepted as conditional")

# 5. New failover slot with safety stop -> hard block regardless of level.
fresh()
REPORTS[("https://bad.example.com/v1", "bad-model", "key-bad")] = verdict(1, False, stop=True, why="TIER0_VIOLATION")
try:
    validate_conf_targets(conf([PRIMARY]), conf([PRIMARY, ("bad-model", "https://bad.example.com/v1", "key-bad")]))
except ValueError as exc:
    assert "slot dự phòng 1" in str(exc), exc
else:
    raise AssertionError("safety_stop failover must be rejected")
print("PASS safety_stop failover rejected")

# 6. New failover slot with no report at all -> raises AuditRequired (subclass of ValueError).
fresh()
try:
    validate_conf_targets(conf([PRIMARY]), conf([PRIMARY, ("never-audited", BASE, "key-none")]))
except AuditRequired as exc:
    assert "slot dự phòng 1" in str(exc), exc
    assert len(exc.audit_targets) == 1
    assert exc.audit_targets[0]["reason"] == "NO_REPORT"
    # INVARIANT: api_key must never leak
    assert "api_key" not in exc.audit_targets[0]
    assert exc._audit_credentials[0]["api_key"] == "key-none"
else:
    raise AssertionError("un-audited failover must raise AuditRequired")
print("PASS un-audited failover rejected with AuditRequired (secret-free)")

# 7. Replacing a broken failover slot: the old backup identity is grandfathered
#    but the replacement still needs its own report (the dead-lock this fixes).
fresh()
REPORTS[(poor[1], poor[0], poor[2])] = verdict(3, False, why="FAILED_QUALITY")
broken = ("qwen/qwen3.8-omni-flash:free", "https://api.xkiro.com/v1", "key-qwen")
before = conf([PRIMARY, broken])
out = validate_conf_targets(before, conf([PRIMARY, poor]))
assert len(out) == 1 and out[0]["slot"] == 1, out
print("PASS broken failover replacement admitted conditionally")

# 8. Presenting an already-existing credential as a new slot stays grandfathered.
fresh()
before = conf([PRIMARY, poor])
out = validate_conf_targets(before, conf([PRIMARY, poor]))
assert out == [], out
print("PASS existing failover grandfathered")

# 9. 3-day-old failover report passes under 7-day TTL.
fresh()
three_days_s = 3 * 86400.0
REPORTS[(poor[1], poor[0], poor[2])] = verdict(3, False, why="FAILED_QUALITY", age_s=three_days_s)
out = validate_conf_targets(conf([PRIMARY]), conf([PRIMARY, poor]))
assert len(out) == 1 and out[0]["slot"] == 1, out
print("PASS 3-day-old failover report admitted under 7-day TTL")

# 10. 3-day-old primary report raises AuditRequired under 24-hour TTL.
fresh()
REPORTS[("https://new.example.com/v1", "stale-primary", "key-new")] = verdict(4, True, age_s=three_days_s)
try:
    validate_conf_targets(conf([PRIMARY]), conf([("stale-primary", "https://new.example.com/v1", "key-new")]))
except AuditRequired as exc:
    assert "slot chính" in str(exc), exc
    assert exc.audit_targets[0]["reason"] == "STALE_REPORT"
    assert exc.audit_targets[0]["age_s"] == three_days_s
else:
    raise AssertionError("stale primary report must raise AuditRequired")
print("PASS 3-day-old primary report raises AuditRequired under 24h TTL")

# 11. Promoting a Level-3 backup model to Slot 0 requires strict primary check.
fresh()
REPORTS[(poor[1], poor[0], poor[2])] = verdict(3, False, why="FAILED_QUALITY")
before = conf([PRIMARY, poor])
try:
    validate_conf_targets(before, conf([poor, PRIMARY]))
except ValueError as exc:
    assert "slot chính" in str(exc), exc
    assert not isinstance(exc, AuditRequired), "fresh level-3 backup must be hard-blocked, not treated as unaudited"
else:
    raise AssertionError("promoting level-3 backup to slot 0 must be rejected")
print("PASS promoting level-3 backup to slot 0 rejected via fresh verdict")

# 12. Promoting a Level-4 backup model to Slot 0 passes cleanly.
fresh()
level4_backup = ("promoted-gemini", BASE, "key-gemini")
REPORTS[(BASE, "promoted-gemini", "key-gemini")] = verdict(4, True)
before_with_gemini = conf([PRIMARY, level4_backup])
out = validate_conf_targets(before_with_gemini, conf([level4_backup, PRIMARY]))
assert out == [], out
print("PASS promoting level-4 backup to slot 0 accepted")

# 13. Drift detection: compares multiset of IDs and slot counts
assert compute_conf_drift([], None) == {"drift": False, "reason": ""}
live_vlm_active = {"credential_ids": ["slot-0", "slot-1"], "n": 2, "index": 0, "manual_hold": False}
slots_match = [{"id": "slot-0", "model": "primary-model"}, {"id": "slot-1", "model": "poor"}]
assert compute_conf_drift(slots_match, live_vlm_active)["drift"] is False

# Reordering the on-disk slot chain triggers drift even during a hot-switch.
live_vlm_switched = {"credential_ids": ["slot-0", "slot-1"], "n": 2, "index": 1, "manual_hold": True}
assert compute_conf_drift(slots_match, live_vlm_switched)["drift"] is False
slots_reordered = list(reversed(slots_match))
assert compute_conf_drift(slots_reordered, live_vlm_switched)["drift"] is True

# Mismatched ID or slot count causes drift alarm
live_vlm_drifted = {"credential_ids": ["slot-old", "slot-1"], "n": 2, "index": 0, "manual_hold": False}
assert compute_conf_drift(slots_match, live_vlm_drifted)["drift"] is True
assert compute_conf_drift(slots_match[:1], live_vlm_active)["drift"] is True

print("PASS ordered drift detection unit checks")

# 14. A candidate promoted to primary with missing safety-stop evidence fails closed.
fresh()
report = {"report_age_s": 0.0, "verdict": {"verdict_level": 4, "memory_permitted": True}}
REPORTS[(poor[1], poor[0], poor[2])] = report
before = conf([PRIMARY, poor])
try:
    validate_conf_targets(before, conf([poor, PRIMARY]))
except ValueError as exc:
    assert "slot chính" in str(exc), exc
else:
    raise AssertionError("missing safety_stop must block primary admission")
# 15. The primary grandfather exception applies only to the unchanged live identity.
fresh()
primary_replaced = ("replacement-primary", "https://new.example.com/v1", "key-replacement")
REPORTS[(primary_replaced[1], primary_replaced[0], primary_replaced[2])] = verdict(4, True)
out = validate_conf_targets(conf([PRIMARY]), conf([primary_replaced]))
assert out == [], out
print("PASS a replacement primary requires and accepts fresh strict audit")

# 17. A shadowed top-level credential remains grandfathered as a failover target.
fresh()
shadowed = conf([PRIMARY])
shadowed["vlm"]["model"] = "top-level-old"
shadowed["vlm"]["api_base"] = "https://top.example.com/v1"
shadowed["vlm"]["api_key"] = "key-top"
restored_top = ("top-level-old", "https://top.example.com/v1", "key-top")
out = validate_conf_targets(shadowed, conf([PRIMARY, restored_top]))
assert out == [], out
print("PASS shadowed top-level identity is grandfathered for failover")

# 18. Operator override (allow_unaudited=True) allows un-audited failovers conditionally but strictly blocks primary.
fresh()
unaudited_failover = ("un-audited-backup", "https://backup.example.com/v1", "key-backup")
out = validate_conf_targets(conf([PRIMARY]), conf([PRIMARY, unaudited_failover]), allow_unaudited=True)
assert len(out) == 1, out
assert out[0]["slot"] == 1 and out[0]["level"] == 0 and "Chưa qua kiểm định an toàn" in out[0]["why"], out
try:
    validate_conf_targets(conf([PRIMARY]), conf([unaudited_failover, PRIMARY]), allow_unaudited=True)
except AuditRequired as exc:
    assert "slot chính" in str(exc)
else:
    raise AssertionError("allow_unaudited=True must strictly require audit for primary slot 0")
print("PASS allow_unaudited admits failovers conditionally while primary strictly requires audit")

print("CONF_TARGET_GATE_OK")
