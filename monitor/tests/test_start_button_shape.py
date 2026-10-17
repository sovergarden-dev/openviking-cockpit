"""New 'Chạy OpenViking' button: shape, wiring, and the manual-start flow."""
import py_compile
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
src = SRC.read_text(encoding='utf-8')

py_compile.compile(str(SRC), doraise=True)

assert 'text="Chạy OpenViking"' in src, "missing start button"
assert 'def do_start_ov' in src, "missing do_start_ov"
assert 'start_btn.configure(command=do_start_ov)' in src, "start button not wired"
assert '"start_done"' in src, "missing start_done event"
assert 'schtasks", "/Run", "/TN", TASK_NAME' in src, "start flow must run the task"
assert 'OpenViking đang tắt · bấm Chạy OpenViking' in src, "sentence must point at the start button"
assert 'muted=False' in src, "set_dot must accept muted"
assert 'muted=not snap.get("ov_up") and not wd' in src, "watchdog dot must mute when ov is off"

begin = src.split('def begin_restart')[1].split('def do_start_ov')[0]
assert 'start_btn.configure(state="disabled")' in begin, "begin_restart must disable start_btn"

done = src.split('elif kind == "start_done"')[1].split('except queue.Empty')[0]
assert 'start_btn.configure(state="normal")' in done, "start_done must re-enable start_btn"
assert 'health_ok' in done and 'schtasks /Run rc=' in done

restart_done = src.split('elif kind == "restart_done"')[1].split('elif kind == "start_done"')[0]
assert 'start_btn.configure(state="normal")' in restart_done, "restart_done must re-enable start_btn"

start_fn = src.split('def do_start_ov')[1].split('restart_btn.configure(command=do_restart)')[0]
assert 'ov_up' in start_fn, "start flow must no-op when already running"
assert 'task_status == "running"' in start_fn, "start flow must recover a stuck watchdog loop"

print("START_BUTTON_SHAPE_OK")
