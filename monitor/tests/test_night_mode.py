import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='night_test')
src = (ROOT / 'openviking-monitor.pyw').read_text(encoding='utf-8')
rt = (ROOT / 'reserve_table.py').read_text(encoding='utf-8')

assert callable(ns.get('apply_dark_theme')), 'dark theme helper missing'
assert 'apply_dark_theme(root)' in src, 'theme not applied in run_gui'
assert 'theme_use("clam")' in src, 'clam theme not selected'
assert 'DWMWA_USE_IMMERSIVE_DARK_MODE' in src, 'dark title bar not requested'
for style_name in ('Treeview', 'Treeview.Heading', 'TCombobox', 'TEntry', 'TCheckbutton', 'TButton', 'TScrollbar'):
    assert style_name in src, f'{style_name} not themed'

check_line = next((l for l in rt.splitlines() if "text='Ghi chú'" in l), '')
assert check_line, 'Ghi chú checkbox missing'
assert 'self.optional_btn' in check_line, 'Ghi chú phải là nút tick của bảng'
assert 'top_row' not in rt, 'thanh lọc đã gộp một hàng: không còn top_row riêng'
assert "text='Tìm:'" in rt and '.grid(' in rt, 'thanh lọc phải dùng grid (hiện ngay, không chờ Configure)'
assert 'def relayout' in rt, 'thiếu xử lý xuống hàng khi cửa sổ hẹp'
assert 'self._narrow' in rt, 'xử lý xuống hàng phải nhớ trạng thái (đã từng hỏng: mất ô Tìm)'
assert '.place(' not in rt.split('def render')[0], 'thanh lọc không được quay lại dùng place'
assert 'filter_controls.append(ttk.Checkbutton' not in rt, 'Ghi chú still wraps with the filter list'
assert "grid(row=0, column=0, sticky='w')" not in rt, 'old grid layout still present'
assert 'grid(row=1, column=0, columnspan=4' not in rt, 'grid/pack mixed in the filter bar'

print('NIGHT_MODE_OK')
