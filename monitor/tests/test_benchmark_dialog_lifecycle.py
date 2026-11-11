"""Regression coverage for benchmark events after their modal is closed."""
from pathlib import Path
import runpy
import tkinter as tk
from tkinter import ttk

ROOT = Path(__file__).resolve().parents[1]
ns = runpy.run_path(str(ROOT / "openviking-monitor.pyw"), run_name="benchmark_lifecycle_test")
GUI = ns["run_gui"].__globals__
process_event = GUI.get("process_benchmark_event")
bind_escape = GUI.get("bind_escape_to_close")
assert callable(process_event), "missing benchmark event handler"
assert callable(bind_escape), "missing Escape-close binding helper"

root = tk.Tk()
root.geometry("320x180+20+20")
root.update()
try:
    result_win = tk.Toplevel(root)
    progress = tk.StringVar(master=root, value="running")
    table = ttk.Treeview(result_win, columns=("model",), show="headings")
    table.pack()
    probe = tk.Button(result_win, state="disabled")
    bench = tk.Button(result_win, state="disabled")
    done = ("benchmark_done", result_win, progress, [{
        "model": "fixture/model", "median_ms": 10, "p90_ms": 12,
        "best_ms": 8, "worst_ms": 12, "ok_runs": 3, "runs": 3,
    }], table, probe, bench)
    bind_escape(result_win)
    result_win.update()
    result_win.focus_force()
    result_win.update()
    result_win.event_generate("<Escape>", when="now")
    root.update()
    assert not result_win.winfo_exists(), "Escape must close the benchmark result window"
    process_event(done)

    failed_win = tk.Toplevel(root)
    failed_progress = tk.StringVar(master=root, value="running")
    failed_probe = tk.Button(failed_win, state="disabled")
    failed_bench = tk.Button(failed_win, state="disabled")
    bind_escape(failed_win)
    failed_win.update()
    failed_win.focus_force()
    failed_win.update()
    failed_win.event_generate("<Escape>", when="now")
    root.update()
    assert not failed_win.winfo_exists(), "Escape must close the failed benchmark window"
    process_event(("benchmark_failed", failed_win, failed_progress, failed_probe, failed_bench))

    stale_owner = tk.Toplevel(root)
    stale_win = tk.Toplevel(stale_owner)
    stale_progress = tk.StringVar(master=root, value="old run")
    stale_table = ttk.Treeview(stale_win, columns=("model",), show="headings")
    stale_probe = tk.Button(stale_owner, state="disabled")
    stale_bench = tk.Button(stale_owner, state="disabled")
    stale_done = ("benchmark_done", stale_win, stale_progress, done[3], stale_table, stale_probe, stale_bench)
    stale_win.destroy()
    new_win = tk.Toplevel(stale_owner)
    new_progress = tk.StringVar(master=root, value="new run")
    new_table = ttk.Treeview(new_win, columns=("model",), show="headings")
    process_event(stale_done)
    assert stale_probe.cget("state") == "disabled", "stale completion must not enable buttons for a newer run"
    assert stale_bench.cget("state") == "disabled", "stale completion must not enable buttons for a newer run"
    assert new_progress.get() == "new run" and not new_table.get_children()
    stale_failed = ("benchmark_failed", stale_win, stale_progress, stale_probe, stale_bench)
    process_event(stale_failed)
    assert stale_progress.get() == "old run", "stale failure must not update a newer dialog"

    live_win = tk.Toplevel(root)
    live_progress = tk.StringVar(master=root, value="running")
    live_table = ttk.Treeview(live_win, columns=("model", "median"), show="headings")
    live_table.pack()
    live_probe = tk.Button(live_win, state="disabled")
    live_bench = tk.Button(live_win, state="disabled")
    live_done = ("benchmark_done", live_win, live_progress, done[3], live_table, live_probe, live_bench)
    process_event(live_done)
    assert live_table.get_children(), "live benchmark result should still render"
    assert live_progress.get().startswith("Xong"), live_progress.get()
    assert live_probe.cget("state") == "normal"
    assert live_bench.cget("state") == "normal"
    print("BENCHMARK_DIALOG_LIFECYCLE_OK")
finally:
    root.destroy()
