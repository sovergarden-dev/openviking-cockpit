"""Configuration Gate and Admission Policy for OpenViking Cockpit (conf_gate.py).

Pure, standalone logic for target validation, admission classification,
TTL management, and configuration drift detection.
Zero Tkinter dependencies, zero AST-injection dependencies.

Architecture:
- Primary Slot 0: Strict standard (24h TTL, memory_permitted=True, safety_stop=False).
  Slot 0 promotion restriction: Grandfathering applies to Slot 0 ONLY if the identical
  credential identity was already at Slot 0 in 'before'. Promoting a backup to Slot 0
  requires strict primary admission.
- Failover Slots >= 1: Relaxed standard (7-day TTL, Level >= 3, safety_stop=False, conditional admission).
- Two-call layered query: fresh probe under slot TTL, followed by stale probe sentinel if missing.
  Tolerates missing report_age_s safely because fresh probe validates TTL inside auditor.
- INVARIANT: Zero credential secrets in return dictionaries.
"""
from __future__ import annotations

import hashlib
import math
from urllib.parse import urlsplit, urlunsplit


# Admission TTL Policies
AUDIT_TTL_PRIMARY_S: float = 86400.0         # 24 hours for primary slot 0
AUDIT_TTL_FAILOVER_S: float = 7 * 86400.0     # 7 days (604,800s) for failover slots >= 1
AUDIT_TTL_STALE_PROBE_S: float = 3650 * 86400.0  # 10 years finite sentinel for single-pass stale probe


class AuditRequired(ValueError):
    """Raised when an un-audited or expired target requires inline security verification."""
    def __init__(self, message: str, targets: list[dict] | None = None, credentials: list[dict] | None = None):
        super().__init__(message)
        self.audit_targets = targets or []
        self._audit_credentials = credentials or []


def audit_max_age_s(slot_index: int | None = None) -> float:
    """Return maximum allowable audit report age in seconds for a given slot index."""
    return AUDIT_TTL_PRIMARY_S if (slot_index is not None and slot_index == 0) else AUDIT_TTL_FAILOVER_S


def normalize_endpoint(base: str | None) -> str:
    """Normalize endpoint URL to canonical lowercase scheme/host without trailing slash."""
    if not base:
        return ""
    parsed = urlsplit(base.strip())
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), parsed.query, ""))


def model_cache_key(base: str, key: str) -> str:
    """Unique cache key binding normalized endpoint to hashed credential."""
    normalized = normalize_endpoint(base)
    return normalized + "#credential=" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def vlm_credentials_list(vlm: dict) -> list[dict]:
    """Extract list of credential dictionaries from vlm configuration block."""
    creds = vlm.get("credentials")
    if isinstance(creds, list) and creds:
        return [dict(c) for c in creds]
    out = [{
        "id": "credential-0",
        "provider": vlm.get("provider"),
        "model": vlm.get("model"),
        "api_key": vlm.get("api_key"),
        "api_base": vlm.get("api_base"),
    }]
    b = vlm.get("backup")
    if isinstance(b, dict) and b.get("model"):
        out.append({
            "id": "credential-1",
            "provider": b.get("provider") or vlm.get("provider"),
            "model": b.get("model"),
            "api_key": b.get("api_key") or vlm.get("api_key"),
            "api_base": b.get("api_base") or vlm.get("api_base"),
        })
    return out


def effective_credentials(raw: dict) -> list[dict]:
    """Return list of effective credentials taking top-level fallbacks into account."""
    vlm = raw.get("vlm") or {}
    out = []
    for i, credential in enumerate(vlm_credentials_list(vlm)):
        out.append(dict(
            credential,
            model=credential.get("model") or (vlm.get("model") if i == 0 else None),
            api_base=credential.get("api_base") or vlm.get("api_base") or "",
            api_key=credential.get("api_key") or vlm.get("api_key") or "",
        ))
    return out


def _resolved_key(raw_key: str | None) -> str | None:
    """Resolve a config secret reference without exposing failure details."""
    if not isinstance(raw_key, str) or not raw_key.strip():
        return None
    try:
        from secret_store import resolve_secret, SecretStatus
        resolved = resolve_secret(raw_key)
        return resolved.value if resolved.status is SecretStatus.SECRET_READY else None
    except Exception:
        return None


def credential_identity(item: dict) -> tuple:
    """Bind model and endpoint to a resolved credential without retaining raw key text."""
    raw_key = (item.get("api_key") or "").strip()
    resolved = _resolved_key(raw_key)
    key_material = resolved if resolved is not None else "unresolved:" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return (item.get("model") or "", model_cache_key(item.get("api_base") or "", key_material))


def credential_id(model: str | None, base: str | None, raw_key: str | None) -> str:
    """Stable, non-secret credential ID. Resolves env/DPAPI values before hashing."""
    raw = (raw_key or "").strip()
    resolved = _resolved_key(raw)
    material = resolved if resolved is not None else "unresolved:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
    scope = (model or "") + "\0" + model_cache_key(base or "", material)
    return "credential-" + hashlib.sha256(scope.encode("utf-8")).hexdigest()[:32]


def classify_conf_targets(before: dict, after: dict) -> dict:
    """Classify all credential targets in candidate 'after' state.

    Grandfathering rule:
      Any credential identity already configured in 'before' (including top-level vlm.model)
      is grandfathered for failover slots (index >= 1).
      For slot 0 (primary): grandfathering ONLY applies if the identical identity was already
      at slot 0 in 'before'. Promoting a backup or weak model to slot 0 is not grandfathered.

    Returns dict with keys:
      'admitted': list of targets admitted cleanly
      'conditional': list of targets admitted conditionally (Level 3, no safety stop, failover slot >= 1)
      'needs_audit': list of targets lacking a fresh valid report within slot TTL
      'blocked': list of targets with hard violations (safety_stop, level < 3, empty key)

    INVARIANT: No credential secrets (api_key) ever leak into the return dictionaries.
    """
    before_creds = effective_credentials(before)
    existing_all = {credential_identity(item) for item in before_creds}

    vlm_before = before.get("vlm") or {}
    primary_before_ids = set()
    if before_creds:
        primary_before_ids.add(credential_identity(before_creds[0]))
    if vlm_before.get("model"):
        top_identity = credential_identity({
            "model": vlm_before.get("model"),
            "api_base": vlm_before.get("api_base") or "",
            "api_key": vlm_before.get("api_key") or "",
        })
        primary_before_ids.add(top_identity)
        existing_all.add(top_identity)

    blocked = []
    needs_audit = []
    conditional = []
    admitted = []

    for index, item in enumerate(effective_credentials(after)):
        identity = credential_identity(item)
        model = item.get("model") or ""
        base = item.get("api_base") or ""
        slot_name = "slot chính" if index == 0 else f"slot dự phòng {index}"

        # 1. Grandfathering evaluation
        if index == 0 and identity in primary_before_ids:
            admitted.append({"slot": 0, "model": model, "api_base": base})
            continue
        if index >= 1 and identity in existing_all:
            admitted.append({"slot": index, "model": model, "api_base": base})
            continue

        # 2. Resolve the key before audit. Never treat DPAPI ciphertext or unresolved
        # environment references as provider credentials.
        api_key = _resolved_key(item.get("api_key"))
        if not api_key:
            blocked.append({
                "slot": index,
                "model": model,
                "api_base": base,
                "reason": "EMPTY_OR_UNRESOLVED_KEY",
                "message": f"API key thiếu hoặc chưa giải mã được cho {slot_name}; chưa ghi ov.conf.",
            })
            continue

        # 3. Audit report query under a finite age sentinel.
        # so slot-specific TTL policy is applied here, not hidden in the auditor default.
        report = None
        try:
            from provider_security_auditor import get_latest_audit_report
            report = get_latest_audit_report(base, model, max_age_s=AUDIT_TTL_STALE_PROBE_S, api_key=api_key)
        except Exception:
            report = None

        if not report:
            needs_audit.append({
                "slot": index,
                "model": model,
                "api_base": base,
                "reason": "NO_REPORT",
                "age_s": None,
            })
            continue

        age_val = report.get("report_age_s")
        if isinstance(age_val, bool) or not isinstance(age_val, (int, float)) or not math.isfinite(age_val) or age_val < 0:
            needs_audit.append({
                "slot": index,
                "model": model,
                "api_base": base,
                "reason": "INVALID_REPORT_AGE",
                "age_s": None,
            })
            continue
        age_s = float(age_val)
        ttl = audit_max_age_s(index)
        if age_s > ttl:
            needs_audit.append({
                "slot": index,
                "model": model,
                "api_base": base,
                "reason": "STALE_REPORT",
                "age_s": age_s,
            })
            continue

        verdict = report.get("verdict") if isinstance(report, dict) else None
        if not isinstance(verdict, dict):
            blocked.append({
                "slot": index, "model": model, "api_base": base,
                "reason": "INVALID_VERDICT",
                "message": f"Kiểm định trả về kết luận không hợp lệ cho {slot_name}; chưa ghi ov.conf.",
            })
            continue
        permitted_value = verdict.get("memory_permitted")
        safety_value = verdict.get("safety_stop")
        level = verdict.get("verdict_level")
        if type(permitted_value) is not bool or type(safety_value) is not bool:
            blocked.append({
                "slot": index, "model": model, "api_base": base,
                "reason": "INVALID_VERDICT_FIELDS",
                "message": f"Kiểm định thiếu bằng chứng safety/memory hợp lệ cho {slot_name}; chưa ghi ov.conf.",
            })
            continue
        permitted = permitted_value and not safety_value
        safety_stop = safety_value
        level_ok = type(level) is int and level >= 3

        if safety_stop or not level_ok:
            blocked.append({
                "slot": index,
                "model": model,
                "api_base": base,
                "reason": "SAFETY_STOP" if safety_stop else "LEVEL_TOO_LOW",
                "message": f"Chạy kiểm định an toàn trước cho đúng Base URL, model và API key ({slot_name}). Cần báo cáo còn hạn, hợp lệ và cho phép memory; chưa ghi ov.conf.",
            })
        elif index == 0 and not permitted:
            blocked.append({
                "slot": 0,
                "model": model,
                "api_base": base,
                "reason": "PRIMARY_NOT_PERMITTED",
                "message": f"Chạy kiểm định an toàn trước cho đúng Base URL, model và API key ({slot_name}). Cần báo cáo còn hạn, hợp lệ và cho phép memory; chưa ghi ov.conf.",
            })
        elif index >= 1 and level == 3 and not permitted:
            conditional.append({
                "slot": index,
                "model": model,
                "api_base": base,
                "level": level,
                "why": verdict.get("why") or "",
            })
        elif not permitted:
            blocked.append({
                "slot": index,
                "model": model,
                "api_base": base,
                "reason": "MEMORY_NOT_PERMITTED",
                "message": f"Kiểm định không cho phép memory cho {slot_name}; chưa ghi ov.conf.",
            })
        else:
            admitted.append({"slot": index, "model": model, "api_base": base, "level": level})

    return {
        "blocked": blocked,
        "needs_audit": needs_audit,
        "conditional": conditional,
        "admitted": admitted,
    }


def validate_conf_targets(before: dict, after: dict, *, allow_unaudited: bool = False) -> list[dict]:
    """Validate targets against admission criteria.

    Raises:
      - AuditRequired (subclass of ValueError) with .audit_targets if retriable by running audit.
      - ValueError if hard-blocked (safety_stop, level < 3, empty key).

    Returns:
      - List of conditional failover targets requiring operator confirmation.
    """
    plan = classify_conf_targets(before, after)
    blocked = plan.get("blocked") or []
    needs_audit = plan.get("needs_audit") or []
    conditional = list(plan.get("conditional") or [])

    if blocked:
        first = blocked[0]
        slot_name = "slot chính" if first["slot"] == 0 else f"slot dự phòng {first['slot']}"
        raise ValueError(
            first.get("message") or
            f"Chạy kiểm định an toàn trước cho đúng Base URL, model và API key ({slot_name}). Cần báo cáo còn hạn, hợp lệ và cho phép memory; chưa ghi ov.conf."
        )

    if needs_audit:
        unaudited_primaries = [t for t in needs_audit if t["slot"] == 0]
        if allow_unaudited and not unaudited_primaries:
            for t in needs_audit:
                conditional.append({
                    "slot": t["slot"],
                    "model": t["model"],
                    "api_base": t["api_base"],
                    "level": 0,
                    "why": "Chưa qua kiểm định an toàn (người dùng chủ động tự kiểm sau)",
                })
        else:
            first = unaudited_primaries[0] if unaudited_primaries else needs_audit[0]
            slot_name = "slot chính" if first["slot"] == 0 else f"slot dự phòng {first['slot']}"
            targets = [{k: v for k, v in item.items() if k != "api_key"} for item in needs_audit]
            all_credentials = effective_credentials(after)
            audit_credentials = []
            for target in needs_audit:
                index = target["slot"]
                if index < 0 or index >= len(all_credentials):
                    raise ValueError(f"Slot {index} nằm ngoài danh sách cấu hình; chưa ghi ov.conf.")
                item = all_credentials[index]
                resolved_key = _resolved_key(item.get("api_key"))
                if not resolved_key:
                    raise ValueError(f"API key thiếu hoặc chưa giải mã được cho slot {index}; chưa ghi ov.conf.")
                audit_credentials.append({"slot": index, "model": item.get("model"), "api_base": item.get("api_base"), "api_key": resolved_key})
            err = AuditRequired(
                f"Chạy kiểm định an toàn trước cho đúng Base URL, model và API key ({slot_name}). Cần báo cáo còn hạn, hợp lệ và cho phép memory; chưa ghi ov.conf.",
                targets=targets,
                credentials=audit_credentials,
            )
            raise err

    return conditional


def compute_conf_drift(conf_slots: list[dict], live_vlm: dict | None, live_models: dict | None = None) -> dict:
    """Detect slot-chain drift using the ordered credential-ID list.

    Active-index changes and manual failover holds do not alter configuration order.
    Comparing order catches priority changes as well as slot count and identity changes.
    """
    if not live_vlm or not isinstance(live_vlm, dict):
        return {"drift": False, "reason": ""}
    live_ids = live_vlm.get("credential_ids")
    if not isinstance(live_ids, list) or not live_ids:
        return {"drift": False, "reason": ""}
    conf_ids = [slot.get("id") for slot in conf_slots if slot.get("id")]
    if conf_ids == ["default"]:
        conf_ids = ["credential-0"]
    if live_vlm.get("n") != len(conf_slots) or conf_ids != live_ids:
        return {"drift": True, "reason": "Chuỗi slot hoặc thứ tự ưu tiên trên đĩa khác cấu hình máy chủ đang chạy."}
    return {"drift": False, "reason": ""}
