"""Runtime VLM hot-switch wiring: endpoint use + hold display + messages."""
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
src = SRC.read_text(encoding='utf-8')

assert 'OV_VLM_ACTIVE = "http://127.0.0.1:19330/api/v1/observer/vlm/active"' in src
assert 'a_code, a_body = http_json(OV_VLM_ACTIVE, timeout=3) if h_code == 200 else (None, None)' in src
assert 'live = res' in src and 'active = int(res["index"])' in src

sw = src.split('def do_switch')[1].split('def do_move')[0]
assert 'method="POST"' in sw
assert '{"index": idx}' in sw
assert 'đã khóa failback (bấm slot 1 Chính để mở)' in sw
assert 'auto failback đã bật lại' in sw
assert 'promote_slot' not in sw and 'begin_restart' not in sw

assert 'hold_now' in src
assert 'khóa failback' in src and 'slot 1' in src, 'UI phải hiển thị khóa failback và cách mở'
assert 'manual_hold' in src

print("VLM_ACTIVE_WIRING_OK")
