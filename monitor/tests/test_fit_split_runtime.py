"""Keep the Tk event loop responsive at the minimum window and four slots."""
import os
import runpy
import sys
import tkinter as tk
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ["MONITOR_NO_AUTOFIT"] = "1"
ns = runpy.run_path(str(ROOT / "openviking-monitor.pyw"), run_name="fit_split_runtime_test")
globals_ = ns["run_gui"].__globals__

slots = [
    {"index": i, "id": f"fixture-{i}", "model": f"fixture/model-{i}",
     "api_base": "https://fixture.invalid/v1", "api_key": "synthetic-key"}
    for i in range(4)
]
fixture_conf = {
    "primary": slots[0]["model"], "api_base": slots[0]["api_base"], "api_key": "synthetic-key",
    "thinking": True, "max_retries": 2, "failback_timeout_seconds": 3600,
    "failback_request_count": 2147483647, "slots": slots,
}
globals_["load_state"] = lambda: {
    "geometry": "880x560", "geometry_autofit": True, "manual_split": False,
    "reserve_split": 0, "spare_models": [], "model_lists": {},
    "reserve_layout": {}, "probe": {}, "auto_probe_enabled": False,
}
globals_["save_state"] = lambda _state: None
globals_["read_ov_conf"] = lambda resolve_env=False: fixture_conf

original_mainloop = tk.Tk.mainloop
result = {"ticks": 0, "error": None, "geometry": None}

def guarded_mainloop(root, *args):
    def heartbeat():
        try:
            root.update_idletasks()
            result["ticks"] += 1
            if result["ticks"] < 6:
                root.after(100, heartbeat)
            else:
                result["geometry"] = root.winfo_geometry()
                root.destroy()
        except tk.TclError as exc:
            result["error"] = str(exc)
            root.destroy()
    root.after(100, heartbeat)
    original_mainloop(root, *args)

tk.Tk.mainloop = guarded_mainloop
try:
    ns["run_gui"](start_hidden=False)
finally:
    tk.Tk.mainloop = original_mainloop

assert result["error"] is None, result["error"]
assert result["ticks"] == 6, result
assert result["geometry"].startswith("880x560"), result["geometry"]
print("FIT_SPLIT_MINIMUM_WINDOW_RESPONSIVE_OK")
