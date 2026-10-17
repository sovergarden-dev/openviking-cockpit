import ast
from pathlib import Path
p = Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
src = p.read_text(encoding="utf-8")
t = ast.parse(src)
assert "spare_list.bind" in src and "Double-Button-1" in src, "missing double-click bind"
assert "edit_selected_spare" in src
assert "slot_editor(\"spare\", item)" in src or "slot_editor('spare', item)" in src
print("SPARE_DOUBLE_CLICK_SHAPE_OK")
