"""Cancellation signal and modal cleanup contract for the benchmark worker."""
from pathlib import Path
import runpy
import sys
import threading
import tkinter as tk

ROOT = Path(__file__).resolve().parents[1]
ns = runpy.run_path(str(ROOT / "openviking-monitor.pyw"), run_name="benchmark_cancel_test")
run_work = ns.get("run_benchmark_work")
bind_close = ns.get("bind_benchmark_close")
assert callable(run_work), "missing cancellable benchmark worker"
assert callable(bind_close), "missing benchmark window close binding"

cancel = threading.Event()
calls = []
def probe(model, _base, _key):
    calls.append(model)
    cancel.set()
    return {"ok": True, "ms": 5, "text": "5 ms"}

results, cancelled = run_work(["first", "second"], 3, "https://fixture.invalid/v1", "synthetic-key", probe, cancel)
assert cancelled is True
assert calls == ["first"], calls
assert results == [], results

root = tk.Tk()
try:
    parent = tk.Toplevel(root)
    parent.grab_set()
    result = tk.Toplevel(parent)
    probe_button = tk.Button(parent, state="disabled")
    bench_button = tk.Button(parent, state="disabled")
    close_event = threading.Event()
    bind_close(result, parent, close_event, probe_button, bench_button)
    result.update()
    result.focus_force()
    result.update()
    result.event_generate("<Escape>", when="now")
    root.update()
    assert close_event.is_set(), "Escape must signal the benchmark worker to stop"
    assert not result.winfo_exists(), "Escape must close the benchmark window"
    assert root.grab_current() == parent, "closing child modal must restore editor modality"
    assert probe_button.cget("state") == "normal"
    assert bench_button.cget("state") == "normal"

    delete_event = threading.Event()
    result2 = tk.Toplevel(parent)
    close_result2 = bind_close(result2, parent, delete_event, probe_button, bench_button)
    protocol_script = result2.protocol("WM_DELETE_WINDOW")
    result2.tk.call("eval", protocol_script)
    root.update()
    assert delete_event.is_set(), "registered window-manager close callback must cancel the worker"
    assert not result2.winfo_exists()

    broken_parent = tk.Toplevel(root)
    broken_result = tk.Toplevel(broken_parent)
    def destroyed_parent():
        raise tk.TclError("parent already destroyed")
    broken_parent.winfo_exists = destroyed_parent
    broken_event = threading.Event()
    close_broken = bind_close(broken_result, broken_parent, broken_event, probe_button, bench_button)
    close_broken()
    assert broken_event.is_set()
    assert not broken_result.winfo_exists()

    direct_parent = tk.Toplevel(root)
    direct_parent.grab_set()
    direct_result = tk.Toplevel(direct_parent)
    direct_event = threading.Event()
    bind_close(direct_result, direct_parent, direct_event, probe_button, bench_button)
    direct_result.destroy()
    root.update()
    assert direct_event.is_set(), "direct result-window destruction must cancel the worker"
    assert probe_button.cget("state") == "normal"
    assert bench_button.cget("state") == "normal"
    assert root.grab_current() == direct_parent
    print("BENCHMARK_CANCELLATION_OK")
finally:
    root.destroy()
