from pathlib import Path
src = (Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw').read_text(encoding="utf-8")
assert 'spare_list.bind("<Delete>"' in src, "missing Delete key bind on spare list"
assert "def delete_selected_spare(" in src
print("SPARE_DELETE_KEY_SHAPE_OK")
