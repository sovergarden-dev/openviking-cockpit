"""UI spy tests for the redesigned 3-tab security audit report dialog."""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

import pytest

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_auditor_recovery import psa, SCRATCH, BASE, KEY  # noqa: E402
from test_audit_report_view import _base_seven_results, _make_report, _row  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_ui_test():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as folder:
        with (
            patch.object(psa, "__file__", str(Path(folder) / "auditor.py")),
            patch("socket.create_connection", side_effect=AssertionError("network forbidden")),
        ):
            yield


class SpyHarness:
    def __init__(self, *, clipboard_raises=False, selection_seq=None):
        self.worker = False
        self.widgets = []
        self.threads = []
        self.pending = []
        self.clipboard_calls = []
        self.clipboard_payload = None
        self.clipboard_raises = clipboard_raises
        self.selection_seq = list(selection_seq) if selection_seq is not None else []
        self.tree_item_calls = []
        self.text_get_calls = []
        owner = self

        class Widget:
            def __init__(self, parent=None, **kwargs):
                owner.check()
                self.parent = parent
                self.kwargs = kwargs
                self.bindings = {}
                self.protocols = {}
                self.dead = False
                self.value = kwargs.get("value", "")
                self.rows = []
                owner.widgets.append(self)

            def __getattr__(self, name):
                def call(*args, **kwargs):
                    owner.check()
                    if name == "winfo_exists":
                        return not self.dead
                    if name in ("configure", "config"):
                        self.kwargs.update(kwargs)
                    elif name == "set":
                        self.value = args[0]
                    elif name == "get":
                        if "1.0" in args or not args:
                            owner.text_get_calls.append(args)
                            return "" if args else self.value
                        return self.value
                    elif name == "after":
                        owner.pending.append((self, args[1]))
                        return str(len(owner.pending))
                    elif name == "bind":
                        self.bindings[args[0]] = args[1]
                    elif name == "protocol":
                        self.protocols[args[0]] = args[1]
                    elif name == "delete":
                        if args == ("1.0", "end"):
                            self.value = ""
                    elif name == "insert":
                        # Support both Treeview.insert('', 'end', iid=..., values=...) and Text.insert('1.0', txt)
                        if "values" in kwargs or "iid" in kwargs:
                            self.rows.append((kwargs.get("iid"), kwargs.get("values")))
                            self.value += " " + str(kwargs.get("values"))
                            return None
                        self.value += str(args[-1])
                    elif name == "selection":
                        if owner.selection_seq:
                            return owner.selection_seq.pop(0)
                        return None
                    elif name == "item":
                        owner.tree_item_calls.append((args, kwargs))
                        return None
                    elif name == "clipboard_clear":
                        owner.clipboard_calls.append("clear")
                    elif name == "clipboard_append":
                        owner.clipboard_calls.append("append")
                        if owner.clipboard_raises:
                            raise owner.tk.TclError("clipboard unavailable")
                        owner.clipboard_payload = args[0] if args else ""
                    elif name == "destroy":
                        self.dead = True
                        if "<Destroy>" in self.bindings:
                            self.bindings["<Destroy>"](types.SimpleNamespace(widget=self))
                return call

        class Thread:
            def __init__(self, target, daemon=False):
                self.target = target
                self.daemon = daemon
                owner.threads.append(self)

            def start(self):
                pass

            def run(self):
                owner.worker = True
                try:
                    self.target()
                finally:
                    owner.worker = False

        self.Thread = Thread
        self.tk = types.ModuleType("tkinter")
        for name in ("Toplevel", "Frame", "Label", "Button", "StringVar", "Text"):
            setattr(self.tk, name, Widget)
        self.tk.TclError = RuntimeError
        self.ttk = types.ModuleType("tkinter.ttk")
        self.ttk.Notebook = self.ttk.Treeview = Widget
        self.tk.ttk = self.ttk
        self.root = Widget()

    def check(self):
        assert not self.worker, "Tk touched from worker"

    def pump(self):
        pending, self.pending = self.pending, []
        for widget, callback in pending:
            if not widget.dead:
                callback()

    def window(self):
        return next(w for w in self.widgets if w.parent is self.root)

    def click(self, text):
        next(w for w in self.widgets if w.kwargs.get("text") == text).kwargs["command"]()

    def text(self):
        return str([(w.kwargs, w.value) for w in self.widgets])


def _suspect_report():
    results = _base_seven_results()
    results[3] = _row(
        "tool_call_hijack",
        "WARN",
        "MEDIUM",
        summary="Phát hiện đối số hoặc nội dung bất thường",
        findings=["No tool call: capability not verified."],
        evidence="[] | plain text response",
        duration_ms=420.4,
    )
    results[4] = _row(
        "strict_json_vlm",
        "FAIL",
        "MEDIUM",
        summary="Không tuân thủ RFC 8259 strict JSON",
        findings=["Contains markdown fence ```json"],
        evidence="```json\n{}\n```",
        reason_code="MARKDOWN_WRAPPER",
        duration_ms=510.2,
    )
    results[5] = _row(
        "canary_isolation",
        "INCONCLUSIVE",
        "N/A",
        summary="Timeout ở phiên 2",
        findings=["The read operation timed out"],
        evidence="HTTP None | reason=GATEWAY_TIMEOUT",
        reason_code="GATEWAY_TIMEOUT",
        duration_ms=38064.0,
    )
    report = _make_report(results, total_duration_s=95.128, operational_status="Suy luận hợp lệ (11531 ms)")
    report["verdict"]["api_key"] = KEY
    return report


def test_tab1_and_tab2_surface_culprits_and_preserve_raw_verdict_label():
    harness = SpyHarness(selection_seq=[("probe-0004",), None, (), ("unknown-iid",)])
    report = _suspect_report()
    with (
        patch.dict(sys.modules, {"tkinter": harness.tk, "tkinter.ttk": harness.ttk}),
        patch.object(psa.threading, "Thread", harness.Thread),
        patch.object(psa, "get_latest_audit_report", return_value=report),
    ):
        psa.launch_security_audit_ui(harness.root, BASE, KEY, "fixture/model", cached_report=report)
        harness.pump()

        rendered = harness.text()
        # Tab-1/Tab-2 presentation widgets must never show stale placeholders or unformatted IEEE floats
        non_json_widgets = str([
            (w.kwargs, w.value)
            for w in harness.widgets
            if w.kwargs.get("name") != "t3_raw"
        ])
        assert "Not admitted." not in non_json_widgets
        assert "6.343999" not in non_json_widgets
        # Tab-3 raw JSON must preserve the authoritative projection verbatim
        assert '"use_for": "Not admitted."' in rendered
        assert "6.34 s" in rendered
        assert "38.06 s" in rendered
        assert "76.13 s" in rendered
        assert "95.13 s" in rendered
        assert "tool_call_hijack" in rendered
        assert "strict_json_vlm" in rendered
        assert "canary_isolation" in rendered
        assert "INSUFFICIENT_DATA" in rendered

        # Raw actionable_verdict must remain in a tk.Label
        labels = [w for w in harness.widgets if isinstance(w.kwargs.get("text"), str) and "INSUFFICIENT_DATA" in w.kwargs.get("text", "")]
        assert labels, "raw actionable_verdict must stay visible in a Label"
        # Disclaimer must be pinned in its own Label outside exec_txt, yet kept in clipboard_payload
        disc_labels = [w for w in harness.widgets if isinstance(w.kwargs.get("text"), str) and w.kwargs.get("text", "").startswith("Lưu ý giới hạn:")]
        assert len(disc_labels) == 1, f"expected single pinned disclaimer Label, got {len(disc_labels)}"
        exec_texts = [w.value for w in harness.widgets if isinstance(w.value, str) and "CHỈ DẪN VẬN HÀNH THỰC TẾ" in w.value]
        assert exec_texts and "Lưu ý giới hạn:" not in exec_texts[0]

        # Auto-selected first culprit (tool_call_hijack -> probe-0003) on load, never calling tree.item()
        assert harness.tree_item_calls == []
        assert "No tool call: capability not verified." in rendered

        # Clicking "Xem chi tiết" handles valid tuple, None, empty tuple, and unknown iid cleanly
        harness.click("Xem chi tiết")
        assert "MARKDOWN_WRAPPER" in harness.text()
        harness.click("Xem chi tiết")  # selection() -> None
        harness.click("Xem chi tiết")  # selection() -> ()
        harness.click("Xem chi tiết")  # selection() -> ('unknown-iid',)
        assert harness.tree_item_calls == []
        assert KEY not in harness.text()


def test_tab3_copy_button_spies_redacted_clipboard_without_reading_text_widget():
    harness = SpyHarness()
    report = _suspect_report()
    with (
        patch.dict(sys.modules, {"tkinter": harness.tk, "tkinter.ttk": harness.ttk}),
        patch.object(psa.threading, "Thread", harness.Thread),
        patch.object(psa, "get_latest_audit_report", return_value=report),
    ):
        psa.launch_security_audit_ui(harness.root, BASE, KEY, "fixture/model", cached_report=report)
        harness.pump()
        harness.click("Sao chép báo cáo")

        assert harness.clipboard_calls == ["clear", "append"]
        assert harness.text_get_calls == []
        assert harness.clipboard_payload is not None
        assert "INSUFFICIENT_DATA" in harness.clipboard_payload
        assert "MARKDOWN_WRAPPER" in harness.clipboard_payload
        assert KEY not in harness.clipboard_payload
        # Clipboard tail JSON parses cleanly without internal redaction errors
        json_part = harness.clipboard_payload.rpartition("\n\n")[2]
        parsed_clip = json.loads(json_part)
        assert "_redaction_error" not in parsed_clip
        assert "[UNSUPPORTED_KEY]" not in json_part


def test_clipboard_tclerror_isolated_from_audit_callbacks_and_configure_guard():
    on_complete = Mock()
    on_failure = Mock()
    harness = SpyHarness(clipboard_raises=True)
    report = _suspect_report()
    with (
        patch.dict(sys.modules, {"tkinter": harness.tk, "tkinter.ttk": harness.ttk}),
        patch.object(psa.threading, "Thread", harness.Thread),
        patch.object(psa, "get_latest_audit_report", return_value=report),
    ):
        psa.launch_security_audit_ui(
            harness.root,
            BASE,
            KEY,
            "fixture/model",
            cached_report=report,
            on_complete=on_complete,
            on_failure=on_failure,
        )
        harness.pump()
        harness.click("Sao chép báo cáo")
        assert "Không thể sao chép báo cáo" in harness.text()
        on_complete.assert_not_called()
        on_failure.assert_not_called()

        # Guarded <Configure> handlers must ignore invalid widths cleanly
        for widget in list(harness.widgets):
            cb = widget.bindings.get("<Configure>")
            if cb is not None:
                for bad_width in (None, 1, True, float("nan"), -5, 860):
                    cb(types.SimpleNamespace(width=bad_width))

        # Closed window blocks subsequent copy clicks safely
        harness.window().protocols["WM_DELETE_WINDOW"]()
        before_calls = list(harness.clipboard_calls)
        harness.click("Sao chép báo cáo")
        assert harness.clipboard_calls == before_calls
