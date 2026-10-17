import runpy
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='sentence_test')
sentence = ns['sentence']


def base(**kw):
    snap = {
        "ov_up": True,
        "ollama_up": True,
        "gateway_up": True,
        "listeners": {"ov": [{"pid": 1234}]},
        "queue": {"pending": 0, "errors": 0},
        "conf": {"slots": [{"model": "primary-x"}, {"model": "backup-y"}], "primary": "primary-x"},
        "active": 1,
        "failover": True,
    }
    snap.update(kw)
    return snap


text, tone = sentence(base())
assert tone == "warn", (text, tone)
assert "kiểm tra primary-x" in text, f'primary khác dự phòng thì phải nêu tên primary: {text!r}'

# Cùng một model ở cả hai phía: không lặp tên, không "kiểm tra <tên>".
snap = base(active=0)
snap["conf"] = {"slots": [{"model": "gemini-3.8-flash-high"}], "primary": "gemini-3.8-flash-high"}
text, tone = sentence(snap)
assert tone == "warn", (text, tone)
assert text == "Đang failover sang gemini-3.8-flash-high · đang kiểm tra", f'câu chưa rút gọn: {text!r}'
assert text.count("gemini-3.8-flash-high") == 1, f'tên model bị lặp: {text!r}'

# Không failover thì giữ nguyên hành vi cũ.
text, tone = sentence(base(failover=False))
assert tone == "ok" and text.startswith("Khỏe · "), (text, tone)

# Watchdog treo socket: cổng đóng lâu mà tiến trình còn sống -> chẩn đoán rõ, tone bad
hang = base(ov_up=False)
hang["ov_procs"] = 3
hang["ov_down_since"] = time.time() - 120
hang["task"] = {"status": "Running"}
text, tone = sentence(hang)
assert tone == "bad", (text, tone)
assert "treo socket" in text and "3 tiến trình" in text, text
assert "Khởi động lại" in text, text

# Mới đóng vài giây -> chưa kết luận treo
fresh = base(ov_up=False)
fresh["ov_procs"] = 0
fresh["ov_down_since"] = time.time() - 3
fresh["task"] = {"status": "Running"}
text, tone = sentence(fresh)
assert tone == "bad" and "treo socket" not in text, (text, tone)

# Không tiến trình nào -> đang tắt, mời bấm Chạy
off = base(ov_up=False)
off["ov_procs"] = 0
off["ov_down_since"] = time.time() - 600
off["task"] = {"status": "Ready"}
text, tone = sentence(off)
assert text == "OpenViking đang tắt · bấm Chạy OpenViking" and tone == "warn", (text, tone)

# Có tiến trình nhưng cổng vừa mới đóng -> vẫn là "không lên được" (chưa đủ 15s)
off2 = base(ov_up=False)
off2["ov_procs"] = 2
off2["ov_down_since"] = time.time() - 5
off2["task"] = {"status": "Running"}
text, _ = sentence(off2)
assert "không lên được" in text, text

# Watchdog phải được nuôi từ snapshot thật + log lại
src = (ROOT / 'openviking-monitor.pyw').read_text(encoding='utf-8')
assert '"ov_down_since": OV_DOWN["since"]' in src and '"ov_procs": OV_DOWN["procs"]' in src
assert 'OV hang: port 19330 closed' in src, 'phải ghi log khi phát hiện treo'
assert 'def count_ov_processes' in src
print('SENTENCE_FAILOVER_OK')
