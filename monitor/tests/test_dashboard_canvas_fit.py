"""Fit measures actual Overview content, including the high-DPI scrollbar."""
import ast
from pathlib import Path
from types import SimpleNamespace

source = Path(__file__).resolve().parents[1] / 'openviking-monitor.pyw'
tree = ast.parse(source.read_text(encoding='utf-8-sig'))
node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'dashboard_size')


def widget(width=1, height=1):
    return SimpleNamespace(winfo_reqwidth=lambda: width, winfo_reqheight=lambda: height)


def height_budget(chrome, upper, lower, sash, limit):
    return min(chrome + upper + lower + sash + 8, limit)


content = widget(1900, 700)
root = SimpleNamespace(winfo_height=lambda: 1000, winfo_width=lambda: 880,
                       winfo_screenwidth=lambda: 2400, winfo_screenheight=lambda: 1400,
                       nametowidget=lambda _: SimpleNamespace(winfo_height=lambda: 870))
namespace = dict(root=root, notebook=SimpleNamespace(select=lambda: 'overview', winfo_height=lambda: 900),
                 top=widget(1000), dots=widget(300), upper=widget(height=400), watch_panel=widget(height=200),
                 overview_tab=widget(20), overview_content=content, overview_scroll=widget(16),
                 dpi_scale=2.0, min_width=1760, dashboard_content_height=height_budget)
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
width, height = namespace['dashboard_size']()
assert width >= 1900 + 16 + 40, 'Fit measured Canvas instead of the high-DPI Overview content'
assert 560 <= height <= 1280
namespace['overview_content'] = widget(3000)
assert namespace['dashboard_size']()[0] == 2340, 'Fit exceeded the screen-width budget'
namespace.update(dpi_scale=1.0, min_width=880, overview_tab=widget(960), overview_content=widget(960))
assert namespace['dashboard_size']()[0] == 1036, 'normal-DPI Fit changed'
print('DASHBOARD_CANVAS_FIT_OK')
