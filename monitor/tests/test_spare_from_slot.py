from pathlib import Path
src = (Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw').read_text(encoding="utf-8")
assert 'text="Từ slot"' in src
assert "def copy_slot_to_spare" in src
assert "save_form_as_spare(" in src
print("SPARE_FROM_SLOT_SHAPE_OK")
