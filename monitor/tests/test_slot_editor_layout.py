"""Tk 8.6 runtime geometry contract for slot-editor action zones."""
import os
import runpy
import sys
import tkinter as tk
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["MONITOR_NO_AUTOFIT"] = "1"
TEST_SCALE = float(os.environ.get("MONITOR_TEST_SCALE", "1.333333"))
original_tk_init = tk.Tk.__init__
def scaled_tk_init(root, *args, **kwargs):
    original_tk_init(root, *args, **kwargs)
    root.tk.call("tk", "scaling", TEST_SCALE)
tk.Tk.__init__ = scaled_tk_init
ns = runpy.run_path(str(ROOT / "openviking-monitor.pyw"), run_name="slot_editor_layout_test")
GUI = ns["run_gui"].__globals__
GUI["load_state"] = lambda: {
    "geometry": "1020x640",
    "geometry_autofit": True,
    "spare_models": [],
    "model_lists": {},
    "reserve_layout": {},
    "probe": {},
}
GUI["save_state"] = lambda _state: None
GUI["MAX_SLOTS"] = 5
GUI["read_ov_conf"] = lambda resolve_env=False: {
    "primary": "fixture/model",
    "api_base": "https://fixture.invalid/v1",
    "api_key": "synthetic-key",
    "thinking": True,
    "max_retries": 2,
    "failback_timeout_seconds": 3600,
    "failback_request_count": 2147483647,
    "slots": [
        {"index": index, "id": f"credential-fixture-{index}", "model": f"fixture/model-{index}",
         "api_base": "https://fixture.invalid/v1", "api_key": "synthetic-key"}
        for index in range(4)
    ],
}

original_thread = GUI["threading"].Thread
class NoopThread:
    def __init__(self, target=None, *args, **kwargs):
        self.target = target
        self.kwargs = kwargs
    def start(self):
        if self.kwargs.get("name") == "ov-poll":
            original_thread(target=self.target, daemon=True, name="ui-layout-fixture-poller").start()
GUI["threading"].Thread = NoopThread

original_mainloop = tk.Tk.mainloop
result = {"ok": False, "error": None}


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def text_of(widget):
    try:
        return str(widget.cget("text") or "")
    except (tk.TclError, TypeError):
        return ""


def verify_action_rows(dialog, expected_primary_label):
    dialog.update_idletasks()
    widgets = list(walk(dialog))
    text_items = {text_of(w) for w in widgets}
    required = {"Xác minh", "Thử", "Benchmark 3 lượt", "Kiểm định an toàn", "Hủy", expected_primary_label}
    assert required <= text_items, f"missing dialog controls: {sorted(required - text_items)}"

    def assert_no_overlap(parent):
        buttons = [w for w in parent.winfo_children() if w.winfo_class() == "Button" and w.winfo_ismapped()]
        intervals = sorted((w.winfo_rootx(), w.winfo_rootx() + w.winfo_width(), text_of(w)) for w in buttons)
        for left, right in zip(intervals, intervals[1:]):
            assert left[1] <= right[0], f"button overlap in {parent}: {left} vs {right}"
        for start, end, label in intervals:
            assert end - start >= next(w.winfo_reqwidth() for w in buttons if text_of(w) == label), (
                f"button clipped: {label} width={end-start}"
            )

    diag = next(w for w in widgets if any(text_of(c) == "Benchmark 3 lượt" for c in w.winfo_children()))
    primary = next(w for w in widgets if expected_primary_label in {text_of(c) for c in w.winfo_children()} and any(text_of(c) == "Hủy" for c in w.winfo_children()))
    assert_no_overlap(diag)
    assert_no_overlap(primary)
    scrollbar = next(w for w in widgets if w.winfo_class() == "TScrollbar")
    assert scrollbar.winfo_ismapped() and scrollbar.winfo_width() > 1, "model list scrollbar is hidden"
    assert dialog.winfo_width() <= dialog.winfo_screenwidth() - 40, "dialog exceeds work area width"
    assert dialog.winfo_height() <= dialog.winfo_screenheight() - 40, "dialog exceeds work area height"
    return diag, primary


def test_mainloop(root, *args):
    callback_errors = []
    root.report_callback_exception = lambda exc_type, exc, tb: callback_errors.append((exc_type.__name__, str(exc)))

    def finish_error(exc):
        result["error"] = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
        print("SLOT_EDITOR_LAYOUT_FAIL", result["error"])
        root.destroy()

    def verify_spare():
        try:
            save_spare = next(w for w in walk(root) if text_of(w) == "+ Lưu")
            save_spare.invoke()
            root.update()
            dialog = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            diag, primary = verify_action_rows(dialog, "Lưu dự trữ")
            labels = [text_of(w) for w in primary.winfo_children() if w.winfo_class() == "Button"]
            assert set(labels) == {"Hủy", "Lưu dự trữ"}, labels
            assert diag.winfo_width() == primary.winfo_width()
            print("SLOT_EDITOR_LAYOUT_OK add/edit/spare action zones are mapped and non-overlapping")
            root.destroy()
        except Exception as exc:
            finish_error(exc)

    def verify_edit():
        try:
            dialog = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            diag, primary = verify_action_rows(dialog, "Lưu")
            labels = [text_of(w) for w in primary.winfo_children() if w.winfo_class() == "Button"]
            assert set(labels) == {"Lưu dự trữ", "Hủy", "Lưu"}, labels
            assert diag.winfo_width() == primary.winfo_width()
            next(w for w in walk(dialog) if text_of(w) == "Hủy").invoke()
            root.after(100, verify_spare)
        except Exception as exc:
            finish_error(exc)

    def find_model_button(remaining=20):
        try:
            if callback_errors:
                raise AssertionError(callback_errors)
            candidates = [
                w for w in walk(root)
                if w.winfo_class() == "Button" and w.cget("textvariable")
                and w.winfo_ismapped() and w.winfo_width() > 1
            ]
            if candidates:
                candidates[0].invoke()
                root.after(150, verify_edit)
                return
            if remaining > 0:
                root.after(300, lambda: find_model_button(remaining - 1))
                return
            raise AssertionError("timed out waiting for the first slot model row")
        except Exception as exc:
            finish_error(exc)

    def run():
        try:
            root.geometry(f"1100x{max(900, int(700 * TEST_SCALE / (4.0 / 3.0)))}")
            root.update()
            add_slot = next(w for w in walk(root) if text_of(w) == "+ Thêm dự phòng")
            assert add_slot.cget("state") == "normal", "fixture should allow add-mode modal"
            add_slot.invoke()
            root.update()
            assert not callback_errors, callback_errors
            dialog = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            diag, primary = verify_action_rows(dialog, "Lưu")
            labels = [text_of(w) for w in primary.winfo_children() if w.winfo_class() == "Button"]
            assert set(labels) == {"Lưu dự trữ", "Hủy", "Lưu"}, labels
            assert diag.winfo_width() == primary.winfo_width()
            next(w for w in walk(dialog) if text_of(w) == "Hủy").invoke()
            root.after(300, find_model_button)
        except Exception as exc:
            finish_error(exc)

    root.after(900, run)
    original_mainloop(root, *args)


tk.Tk.mainloop = test_mainloop
try:
    ns["run_gui"](start_hidden=False)
finally:
    GUI["threading"].Thread = original_thread
    tk.Tk.mainloop = original_mainloop

assert result["error"] is None, result["error"]
print("SLOT_EDITOR_LAYOUT_OK")
