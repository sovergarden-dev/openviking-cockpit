"""Test controller thông báo của OpenViking Monitor."""
import os
import sys
from pathlib import Path

MONITOR_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(MONITOR_DIR))

from openviking_monitor_notification import NotificationController


def test_tray_needed():
    nc = NotificationController()
    assert nc.should_have_tray({"run_with_windows": False, "notify_on_down": True, "notify_on_failover": False}) is True
    assert nc.should_have_tray({"run_with_windows": False, "notify_on_down": False, "notify_on_failover": True}) is True
    assert nc.should_have_tray({"run_with_windows": True, "notify_on_down": False, "notify_on_failover": False}) is True
    assert nc.should_have_tray({"run_with_windows": False, "notify_on_down": False, "notify_on_failover": False}) is False
    print("test_tray_needed: PASS")


def test_independent_outage_events():
    nc = NotificationController()
    state = {"notify_on_down": True, "notify_on_failover": True}
    
    # 1. Ban đầu bình thường
    prev = {"ov_up": True, "watchdog_ok": True, "failover": False}
    snap1 = {"ov_up": True, "watchdog_ok": False, "failover": False}
    events = nc.evaluate(prev, snap1, state, now=1000.0, now_mono=10.0)
    assert len(events) == 1
    assert events[0]["kind"] == "watchdog_down"
    nc.acknowledge_delivery("watchdog_down", success=True)
    
    # 2. Sau đó OpenViking cũng sập theo -> phải phát hiện riêng, không bị nuốt
    snap2 = {"ov_up": False, "watchdog_ok": False, "failover": False}
    events2 = nc.evaluate(snap1, snap2, state, now=1010.0, now_mono=20.0)
    assert any(e["kind"] == "ov_down" for e in events2)
    nc.acknowledge_delivery("ov_down", success=True)
    print("test_independent_outage_events: PASS")


def test_failover_and_recovery():
    nc = NotificationController()
    state = {"notify_on_down": True, "notify_on_failover": True}
    
    prev = {"ov_up": True, "watchdog_ok": True, "failover": False}
    snap_down = {"ov_up": False, "watchdog_ok": True, "failover": False}
    e1 = nc.evaluate(prev, snap_down, state, now=2000.0, now_mono=100.0)
    assert len(e1) == 1 and e1[0]["kind"] == "ov_down"
    nc.acknowledge_delivery("ov_down", success=True)
    
    # Sập liên tục nhưng đã gửi thành công -> không spam
    e2 = nc.evaluate(snap_down, snap_down, state, now=2050.0, now_mono=150.0)
    assert len(e2) == 0
    
    # Hồi phục
    snap_up = {"ov_up": True, "watchdog_ok": True, "failover": False}
    e3 = nc.evaluate(snap_down, snap_up, state, now=2100.0, now_mono=200.0)
    assert len(e3) == 0
    
    # Sập lại sau khi đã hồi phục -> phát hiện và sinh cảnh báo mới
    e4 = nc.evaluate(snap_up, snap_down, state, now=2120.0, now_mono=220.0)
    assert len(e4) == 1 and e4[0]["kind"] == "ov_down"
    nc.acknowledge_delivery("ov_down", success=True)
    print("test_failover_and_recovery: PASS")


def test_delivery_failure_and_retry_bound():
    nc = NotificationController(retry_cooldown=30.0, max_retries=2)
    state = {"notify_on_down": True, "notify_on_failover": False}
    prev = {"ov_up": True, "watchdog_ok": True, "failover": False}
    snap_down = {"ov_up": False, "watchdog_ok": True, "failover": False}
    
    # Lần 1: khởi tạo lần đầu (initial attempt), retries = 0
    e1 = nc.evaluate(prev, snap_down, state, now=3000.0, now_mono=10.0)
    assert len(e1) == 1
    nc.acknowledge_delivery("ov_down", success=False)
    assert nc.incidents["ov_down"]["retries"] == 1
    
    # Chưa hết cooldown 30s -> không gửi
    e_wait = nc.evaluate(snap_down, snap_down, state, now=3010.0, now_mono=20.0)
    assert len(e_wait) == 0
    
    # Sau 30s: retry lần 1 (retries = 1 < max_retries=2)
    e2 = nc.evaluate(snap_down, snap_down, state, now=3045.0, now_mono=45.0)
    assert len(e2) == 1
    nc.acknowledge_delivery("ov_down", success=False)
    assert nc.incidents["ov_down"]["retries"] == 2
    
    # Sau 30s tiếp: retries đã bằng 2 (không còn < max_retries) -> dừng retry, không spam
    e3 = nc.evaluate(snap_down, snap_down, state, now=3080.0, now_mono=80.0)
    assert len(e3) == 0
    print("test_delivery_failure_and_retry_bound: PASS")


if __name__ == "__main__":
    test_tray_needed()
    test_independent_outage_events()
    test_failover_and_recovery()
    test_delivery_failure_and_retry_bound()
    print("ALL NOTIFICATION TESTS PASSED CLEANLY")

