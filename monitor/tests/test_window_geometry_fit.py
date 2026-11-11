from pathlib import Path
import runpy

source = Path(__file__).resolve().parents[1] / "openviking-monitor.pyw"
ns = runpy.run_path(str(source), run_name="window_geometry_test")
fit = ns["fit_window_dimension"]
assert fit(640, 850, 1000) == 850
assert fit(900, 700, 1000) == 700
assert fit(820, 700, 1000) == 820
assert fit(640, 1200, 1080) == 1080
assert fit(640, 1200, 1) == 1
assert fit(900, 700, 1000, allow_shrink=False) == 900
assert fit(820, 900, 1000, allow_shrink=False) == 900
assert fit(1200, 1300, 1080, allow_shrink=False) == 1080
content_height = ns["dashboard_content_height"]
assert content_height(136, 456, 270, 9, 1000) == 879
assert content_height(136, 456, 270, 9, 860) == 860
print("WINDOW_GEOMETRY_FIT_OK")
