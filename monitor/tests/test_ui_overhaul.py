"""TDD contract for the OpenViking Cockpit Monitor UI overhaul.

Covers:
1. Restored 3-round Benchmark button in slot_editor alongside Kiểm định an toàn,
   ttk.Scrollbar (no Win95 tk.Scrollbar), no local theme_use reset, Escape bind,
   and dark titlebar helper applied to Toplevel windows.
2. Slate dark cockpit palette (no muddy brown #2a2418 on neutral buttons),
   active slot visual highlight, symmetric MODEL/DỰ TRỮ margins, and structured VẬN HÀNH.
3. ReserveTable semantic row tags (row_ok, row_bad, row_untested, row_even/row_odd)
   and compact '%d/%m %H:%M' timestamp formatting so 'Lần thử' never clips at 880px.
"""
from __future__ import annotations

import ast
import os
import runpy
import sys
import tkinter as tk
from tkinter import ttk
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SRC = ROOT / "openviking-monitor.pyw"
RT_SRC = ROOT / "reserve_table.py"
src = SRC.read_text(encoding="utf-8")
rt_src = RT_SRC.read_text(encoding="utf-8")
ns = runpy.run_path(str(SRC), run_name="ui_overhaul_test")

# 1. Palette & Dark Titlebar helper
assert callable(ns.get("apply_dark_titlebar")), "Missing apply_dark_titlebar(win) helper for Toplevel modals"
assert ns["C_BTN"].lower() != "#2a2418", f"Neutral C_BTN should be slate, not muddy brown: {ns['C_BTN']}"
assert "C_ELEVATED" in ns, "Missing C_ELEVATED surface token for sub-panels/zebra rows"

# 2. slot_editor contracts (AST + source)
ed_src = src.split("def slot_editor")[1].split("def do_add")[0]
assert "tk.Scrollbar(" not in ed_src.replace("ttk.Scrollbar(", ""), (
    "slot_editor still uses classic light tk.Scrollbar instead of ttk.Scrollbar"
)
assert "ttk.Scrollbar(" in ed_src, "slot_editor must use dark-themed ttk.Scrollbar"
assert 'theme_use("clam")' not in ed_src and "theme_use('clam')" not in ed_src, (
    "slot_editor must not reset ttk theme_use locally"
)
assert "do_benchmark" in ed_src, "slot_editor missing do_benchmark"
assert 'text="Benchmark 3 lượt"' in ed_src, "Missing restored 'Benchmark 3 lượt' button in slot_editor"
assert "command=lambda: do_benchmark(3)" in ed_src or "command=do_benchmark" in ed_src, (
    "bench_btn is not wired to do_benchmark"
)
assert 'text="Kiểm định an toàn"' in ed_src, "Missing 'Kiểm định an toàn' button in slot_editor"
assert "<Escape>" in ed_src, "slot_editor should bind <Escape> to close cleanly"

# 3. Toplevel modals use apply_dark_titlebar
for fn_name in ("slot_editor", "open_failback", "open_settings", "ask_save", "apply_selected_spare", "copy_slot_to_spare", "pick_rank"):
    seg = src.split(f"def {fn_name}")[1].split("\n    def ")[0]
    assert "apply_dark_titlebar(" in seg, f"{fn_name} Toplevel does not call apply_dark_titlebar"

# 4. ReserveTable semantic tags & compact timestamp
from reserve_table import ReserveTable

root = tk.Tk()
root.withdraw()
try:
    ns["apply_dark_theme"](root)
    table = ReserveTable(root, preferences={})
    table.pack(fill="both", expand=True)
    sample_items = [
        {
            "model": "gemini-3.8-flash-high",
            "api_base": "http://127.0.0.1:9100/v1",
            "last_probe": {"ok": True, "text": "320 ms", "ms": 320, "at": 1762800000},
            "audit_level": 4,
        },
        {
            "model": "broken-model",
            "api_base": "https://api.example.com/v1",
            "last_probe": {"ok": False, "text": "auth-or-quota · HTTP 401", "ms": 150, "at": 1762800060},
        },
        {
            "model": "untested-model",
            "api_base": "http://localhost:20128/v1",
        },
        {
            "model": "conditional-model",
            "api_base": "https://conditional.example/v1",
            "last_probe": {"ok": True, "text": "420 ms", "ms": 420, "at": 1762800120},
            "audit_level": 3,
        },
        {
            "model": "unsafe-model",
            "api_base": "https://unsafe.example/v1",
            "last_probe": {"ok": True, "text": "300 ms", "ms": 300, "at": 1762800180},
            "audit_level": 1,
        },
        {
            "model": "failed-m4-model",
            "api_base": "https://failed-m4.example/v1",
            "last_probe": {"ok": False, "text": "auth-or-quota · HTTP 401", "ms": 150, "at": 1762800240},
            "audit_level": 4,
        },
    ]
    table.render(sample_items)
    rows = table.tree.get_children()
    assert len(rows) == 6
    by_model = {table.tree.item(iid, "values")[0]: iid for iid in rows}

    # Timestamp should be '%d/%m %H:%M' (length 11, no ':SS' bloat)
    at_val = table.tree.item(by_model["gemini-3.8-flash-high"], "values")[4]
    assert len(at_val) == 11 and ":" in at_val, f"Expected compact DD/MM HH:MM timestamp, got {at_val!r}"

    # Semantic tags distinguish probe result and trust level without treating M3 as fully safe.
    ok_tags = set(table.tree.item(by_model["gemini-3.8-flash-high"], "tags"))
    bad_tags = set(table.tree.item(by_model["broken-model"], "tags"))
    untested_tags = set(table.tree.item(by_model["untested-model"], "tags"))
    conditional_tags = set(table.tree.item(by_model["conditional-model"], "tags"))
    unsafe_tags = set(table.tree.item(by_model["unsafe-model"], "tags"))
    failed_m4_tags = set(table.tree.item(by_model["failed-m4-model"], "tags"))
    assert "audit_4" in ok_tags, f"Expected audit_4 tag on M4 row, got {ok_tags}"
    assert "status_bad" in bad_tags, f"Expected status_bad tag on failing row, got {bad_tags}"
    assert "status_untested" in untested_tags, f"Expected status_untested tag on untested row, got {untested_tags}"
    assert "audit_3" in conditional_tags, f"Expected separate audit_3 tag on conditional M3, got {conditional_tags}"
    assert "audit_1" in unsafe_tags, f"Expected separate audit_1 tag on unsafe M1, got {unsafe_tags}"
    assert "status_ok" in conditional_tags and "status_bad" not in conditional_tags, (
        f"Probe result and audit level are independent signals, got {conditional_tags}"
    )
    assert "status_bad" in failed_m4_tags, f"Failed probe must stay red even with M4 audit, got {failed_m4_tags}"
    assert "audit_4" not in failed_m4_tags, f"Probe failure must not be hidden by audit-level color, got {failed_m4_tags}"
finally:
    root.destroy()

print("UI_OVERHAUL_CONTRACT_OK")
