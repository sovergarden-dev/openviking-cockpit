"""Module điều khiển logic thông báo và theo dõi sự cố cho OpenViking Monitor.
Thiết kế kiến trúc sạch:
1. Tách biệt hoàn toàn: Phát hiện sự cố (Incident Detection) vs Gửi cảnh báo (Notification Dispatch) vs Hiển thị UI (Banner State)
2. Không gộp sai trạng thái: OpenViking (19330) và Watchdog được theo dõi độc lập
3. Hỗ trợ bắt kịp sự cố: Bật notification giữa lúc đang sập vẫn sinh cảnh báo
4. Hỗ trợ chu kỳ Restart thủ công: Kìm nén khi đang restart, phát hiện dứt khoát nếu restart thất bại
5. Hàng đợi có giới hạn (Bounded retry) với monotonic clock, timestamp hiển thị dạng wall clock
6. Diễn đạt trung tính, số Slot chính xác (1-based index).
"""
from __future__ import annotations
import time
from typing import Any, Dict, List, Optional, Tuple


def normalize_snap(snap: Optional[Dict[str, Any]], watchdog_eval_fn=None) -> Dict[str, Any]:
    """Chuẩn hóa dữ liệu snapshot.
    Đánh giá trạng thái task một cách rõ ràng và độc lập với ov_up:
    - Nếu snap có truyền sẵn 'watchdog_ok' dạng boolean (synthetic/test), tôn trọng giá trị đó.
    - Trong production: nếu caller truyền watchdog_eval_fn (chính là hàm watchdog_ok của Monitor),
      dùng trực tiếp làm nguồn chân lý duy nhất (Single Source of Truth).
    - Fallback: đọc dict 'task' từ schtasks:
        + 'disabled' / 'vô hiệu' -> task_ok = False, state = 'disabled'
        + 'running' / 'Running' -> task_ok = True, state = 'running'
        + last_result in ('0', '0x0') -> task_ok = True, state = 'ready_ok'
        + nếu có lỗi error từ schtasks hoặc mã lỗi khác 0 mà không running -> task_ok = False
    """
    if not snap:
        return {
            "ov_up": False,
            "watchdog_ok": False,
            "task_status": "unknown",
            "failover": False,
            "_restarting": False,
            "active": 0,
            "ts": time.time(),
        }
    ov_up = bool(snap.get("ov_up"))
    
    if "watchdog_ok" in snap and isinstance(snap.get("watchdog_ok"), bool):
        task_ok = bool(snap.get("watchdog_ok"))
        task_status = "explicit_boolean"
    elif watchdog_eval_fn is not None:
        try:
            task_ok = bool(watchdog_eval_fn(snap))
            task_status = "evaluated_fn"
        except Exception:
            task_ok = False
            task_status = "eval_error"
    else:
        t = snap.get("task") or {}
        st = str(t.get("status") or "").lower()
        state = str(t.get("state") or "").lower()
        last = str(t.get("last_result") or "").strip().lower()
        has_err = bool(t.get("error"))

        if "disabled" in state or "vô hiệu" in state:
            task_ok = False
            task_status = "disabled"
        elif "running" in st or t.get("status") == "Running":
            task_ok = True
            task_status = "running"
        elif has_err:
            task_ok = False
            task_status = "query_error"
        elif last in {"0", "0x0"}:
            task_ok = True
            task_status = "ready_ok"
        else:
            task_ok = False
            task_status = "failed_result"

    return {
        "ov_up": ov_up,
        "watchdog_ok": task_ok,
        "task_status": task_status,
        "failover": bool(snap.get("failover")),
        "_restarting": bool(snap.get("_restarting")),
        "active": int(snap.get("active") or 0),
        "ts": float(snap.get("ts") or time.time()),
    }


class NotificationController:
    """Quản lý vòng đời phát hiện sự cố, hàng đợi cảnh báo và trạng thái banner."""

    def __init__(self, retry_cooldown: float = 60.0, max_retries: int = 3):
        self.retry_cooldown = retry_cooldown
        self.max_retries = max_retries
        self.incidents: Dict[str, Dict[str, Any]] = {
            "ov_down": {
                "active": False,
                "first_seen": 0.0,
                "notified": False,
                "retries": 0,
                "last_attempt_mono": 0.0,
            },
            "watchdog_down": {
                "active": False,
                "first_seen": 0.0,
                "notified": False,
                "retries": 0,
                "last_attempt_mono": 0.0,
            },
            "failover": {
                "active": False,
                "first_seen": 0.0,
                "notified": False,
                "retries": 0,
                "last_attempt_mono": 0.0,
                "slot_1based": 1,
            },
        }

    @staticmethod
    def should_have_tray(state: Dict[str, Any]) -> bool:
        """Khay hệ thống cần tồn tại nếu người dùng bật bất kỳ thông báo nào hoặc bật chạy cùng Windows."""
        return bool(
            state.get("run_with_windows")
            or state.get("notify_on_down")
            or state.get("notify_on_failover")
        )

    def evaluate(
        self,
        prev_snap: Optional[Dict[str, Any]],
        curr_snap: Dict[str, Any],
        state: Dict[str, Any],
        now: Optional[float] = None,
        now_mono: Optional[float] = None,
        watchdog_fn=None,
    ) -> List[Dict[str, Any]]:
        """Đánh giá snapshot hiện tại và trả về danh sách sự cố cần gửi thông báo."""
        if now is None:
            now = time.time()
        if now_mono is None:
            now_mono = time.monotonic()

        curr = normalize_snap(curr_snap, watchdog_fn)

        # Trong lúc đang chủ động khởi động lại, tạm thời kìm nén cảnh báo sập
        if curr["_restarting"]:
            return []

        notify_down_enabled = bool(state.get("notify_on_down"))
        notify_failover_enabled = bool(state.get("notify_on_failover"))

        pending_events: List[Dict[str, Any]] = []

        # --- 1. Theo dõi sự cố OpenViking Server ---
        inc_ov = self.incidents["ov_down"]
        if not curr["ov_up"]:
            if not inc_ov["active"]:
                inc_ov["active"] = True
                inc_ov["first_seen"] = now
                inc_ov["notified"] = False
                inc_ov["retries"] = 0
                inc_ov["last_attempt_mono"] = 0.0

            if notify_down_enabled and not inc_ov["notified"]:
                can_try = (inc_ov["last_attempt_mono"] == 0.0) or (now_mono - inc_ov["last_attempt_mono"] >= self.retry_cooldown)
                if can_try and inc_ov["retries"] < self.max_retries:
                    pending_events.append({
                        "kind": "ov_down",
                        "title": "OpenViking không phản hồi",
                        "body": "Cổng 19330 không phản hồi kiểm tra sức khỏe.",
                        "first_seen": inc_ov["first_seen"],
                    })
                    inc_ov["last_attempt_mono"] = now_mono
        else:
            if inc_ov["active"]:
                inc_ov["active"] = False
                inc_ov["notified"] = False
                inc_ov["retries"] = 0

        # --- 2. Theo dõi sự cố Watchdog / Scheduled Task ---
        inc_wd = self.incidents["watchdog_down"]
        # Đánh giá dựa trên kết quả chuẩn hóa độc lập từ normalize_snap
        task_down = not curr["watchdog_ok"]
        if task_down:
            if not inc_wd["active"]:
                inc_wd["active"] = True
                inc_wd["first_seen"] = now
                inc_wd["notified"] = False
                inc_wd["retries"] = 0
                inc_wd["last_attempt_mono"] = 0.0

            if notify_down_enabled and not inc_wd["notified"]:
                can_try = (inc_wd["last_attempt_mono"] == 0.0) or (now_mono - inc_wd["last_attempt_mono"] >= self.retry_cooldown)
                if can_try and inc_wd["retries"] < self.max_retries:
                    pending_events.append({
                        "kind": "watchdog_down",
                        "title": "OpenViking Watchdog cảnh báo",
                        "body": "Tác vụ Scheduled Task của OpenViking không khả dụng.",
                        "first_seen": inc_wd["first_seen"],
                    })
                    inc_wd["last_attempt_mono"] = now_mono
        else:
            if inc_wd["active"]:
                inc_wd["active"] = False
                inc_wd["notified"] = False
                inc_wd["retries"] = 0

        # --- 3. Theo dõi sự cố Failover ---
        # Khi server đang sập (không phản hồi), không suy diễn dữ liệu cache slot là failover mới
        inc_fo = self.incidents["failover"]
        if curr["failover"] and curr["ov_up"]:
            slot_num = curr["active"] + 1
            if not inc_fo["active"] or inc_fo.get("slot_1based") != slot_num:
                inc_fo["active"] = True
                inc_fo["first_seen"] = now
                inc_fo["notified"] = False
                inc_fo["retries"] = 0
                inc_fo["last_attempt_mono"] = 0.0
                inc_fo["slot_1based"] = slot_num

            if notify_failover_enabled and not inc_fo["notified"]:
                can_try = (inc_fo["last_attempt_mono"] == 0.0) or (now_mono - inc_fo["last_attempt_mono"] >= self.retry_cooldown)
                if can_try and inc_fo["retries"] < self.max_retries:
                    pending_events.append({
                        "kind": "failover",
                        "title": "OpenViking chuyển slot dự phòng",
                        "body": f"Đang sử dụng Slot {slot_num} (dự phòng).",
                        "first_seen": inc_fo["first_seen"],
                    })
                    inc_fo["last_attempt_mono"] = now_mono
        else:
            if inc_fo["active"]:
                inc_fo["active"] = False
                inc_fo["notified"] = False
                inc_fo["retries"] = 0

        # Nếu cả 2 sự cố cùng phát sinh trong 1 chu kỳ, gộp để không đè mất balloon
        if len(pending_events) >= 2:
            kinds = {ev["kind"] for ev in pending_events}
            if "ov_down" in kinds and "watchdog_down" in kinds:
                pending_events = [ev for ev in pending_events if ev["kind"] not in ("ov_down", "watchdog_down")]
                pending_events.insert(0, {
                    "kind": "ov_and_wd_down",
                    "title": "OpenViking và Watchdog cảnh báo",
                    "body": "Cổng 19330 không phản hồi và Scheduled Task không khả dụng.",
                    "first_seen": inc_ov["first_seen"],
                })

        return pending_events

    def acknowledge_delivery(self, kind: str, success: bool) -> None:
        """Ghi nhận phản hồi gửi balloon từ Windows Shell."""
        target_kinds = ["ov_down", "watchdog_down"] if kind == "ov_and_wd_down" else [kind]
        for k in target_kinds:
            if k in self.incidents:
                inc = self.incidents[k]
                if success:
                    inc["notified"] = True
                    inc["retries"] = 0
                else:
                    inc["notified"] = False
                    inc["retries"] += 1

    def _coalesce(self, events: List[Dict[str, Any]], first_seen: float) -> List[Dict[str, Any]]:
        if len(events) >= 2:
            kinds = {ev["kind"] for ev in events}
            if "ov_down" in kinds and "watchdog_down" in kinds:
                filtered = [ev for ev in events if ev["kind"] not in ("ov_down", "watchdog_down")]
                filtered.insert(0, {
                    "kind": "ov_and_wd_down",
                    "title": "OpenViking và Watchdog cảnh báo",
                    "body": "Cổng 19330 không phản hồi và Scheduled Task không khả dụng.",
                    "first_seen": first_seen,
                })
                return filtered
        return events

    def catchup_pending(self, state: Dict[str, Any], now: Optional[float] = None, now_mono: Optional[float] = None) -> List[Dict[str, Any]]:
        """Bắt kịp thông báo khi người dùng bật cài đặt ngay lúc sự cố đang diễn ra.
        Tuân thủ nghiêm ngặt cùng retry bound, cooldown và gộp thông báo như evaluate().
        """
        if now is None:
            now = time.time()
        if now_mono is None:
            now_mono = time.monotonic()
        
        events: List[Dict[str, Any]] = []
        notify_down_enabled = bool(state.get("notify_on_down"))
        notify_failover_enabled = bool(state.get("notify_on_failover"))

        inc_ov = self.incidents["ov_down"]
        if inc_ov["active"] and notify_down_enabled and not inc_ov["notified"]:
            can_try = (inc_ov["last_attempt_mono"] == 0.0) or (now_mono - inc_ov["last_attempt_mono"] >= self.retry_cooldown)
            if can_try and inc_ov["retries"] < self.max_retries:
                events.append({
                    "kind": "ov_down",
                    "title": "OpenViking không phản hồi",
                    "body": "Cổng 19330 không phản hồi kiểm tra sức khỏe.",
                    "first_seen": inc_ov["first_seen"],
                })
                inc_ov["last_attempt_mono"] = now_mono

        inc_wd = self.incidents["watchdog_down"]
        if inc_wd["active"] and notify_down_enabled and not inc_wd["notified"]:
            can_try = (inc_wd["last_attempt_mono"] == 0.0) or (now_mono - inc_wd["last_attempt_mono"] >= self.retry_cooldown)
            if can_try and inc_wd["retries"] < self.max_retries:
                events.append({
                    "kind": "watchdog_down",
                    "title": "OpenViking Watchdog cảnh báo",
                    "body": "Tác vụ Scheduled Task của OpenViking không khả dụng.",
                    "first_seen": inc_wd["first_seen"],
                })
                inc_wd["last_attempt_mono"] = now_mono

        inc_fo = self.incidents["failover"]
        if inc_fo["active"] and notify_failover_enabled and not inc_fo["notified"]:
            can_try = (inc_fo["last_attempt_mono"] == 0.0) or (now_mono - inc_fo["last_attempt_mono"] >= self.retry_cooldown)
            if can_try and inc_fo["retries"] < self.max_retries:
                slot_num = inc_fo.get("slot_1based", 1)
                events.append({
                    "kind": "failover",
                    "title": "OpenViking chuyển slot dự phòng",
                    "body": f"Đang sử dụng Slot {slot_num} (dự phòng).",
                    "first_seen": inc_fo["first_seen"],
                })
                inc_fo["last_attempt_mono"] = now_mono

        return self._coalesce(events, inc_ov["first_seen"])

    def get_banner_text(self) -> Optional[Tuple[str, str]]:
        """Trả về (nội dung, tone) cho banner cảnh báo trên giao diện chính nếu có sự cố đang tiếp diễn."""
        ov_active = self.incidents["ov_down"]["active"]
        wd_active = self.incidents["watchdog_down"]["active"]
        
        if ov_active and wd_active:
            t_str = time.strftime("%H:%M:%S", time.localtime(self.incidents["ov_down"]["first_seen"]))
            return (f"⚠️ OpenViking (19330) và Watchdog không phản hồi · Phát hiện lúc {t_str}", "bad")
        if ov_active:
            t_str = time.strftime("%H:%M:%S", time.localtime(self.incidents["ov_down"]["first_seen"]))
            return (f"⚠️ OpenViking (19330) không phản hồi · Phát hiện lúc {t_str}", "bad")
        if wd_active:
            t_str = time.strftime("%H:%M:%S", time.localtime(self.incidents["watchdog_down"]["first_seen"]))
            return (f"⚠️ Watchdog không hoạt động · Phát hiện lúc {t_str}", "warn")
        return None
