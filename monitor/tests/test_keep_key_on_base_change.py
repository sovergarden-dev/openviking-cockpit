from pathlib import Path
src = (Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw').read_text(encoding="utf-8")
assert "def on_base_change" not in src, "Base URL change must not rewrite API key"
assert "vars_['model'].set('')" not in src and 'vars_["model"].set("")' not in src, "Base/key change must not wipe typed model"
print("KEEP_KEY_ON_BASE_CHANGE_OK")
