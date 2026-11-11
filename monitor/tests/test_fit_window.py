import runpy, sys, tkinter as tk
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ns = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'openviking-monitor.pyw'), run_name='fit_test')
gui_globals = ns['run_gui'].__globals__
fit_state = gui_globals['load_state']()
fit_state['geometry'] = '1200x900'
fit_state['geometry_autofit'] = True
gui_globals['load_state'] = lambda: dict(fit_state)
original = tk.Tk.mainloop


def loop(root, *args):
    def walk(w):
        yield w
        for c in w.winfo_children():
            yield from walk(c)

    def text_of(w):
        try:
            t = w.cget('text')
            return t if isinstance(t, str) else ''
        except Exception:
            return ''

    def go():
        try:
            root.update_idletasks()
            root.update()
            min_height = root.minsize()[1]
            assert min_height < 900, f'auto-fit minimum was ratcheted to saved geometry: {root.minsize()}'
            btn = next(w for w in walk(root) if text_of(w) == 'Cài đặt')
            btn.invoke()
            root.update_idletasks()
            tops = [w for w in walk(root) if w.winfo_class() == 'Toplevel']
            assert tops, 'cửa sổ Cài đặt không mở'
            fit = [w for w in walk(tops[0]) if text_of(w) == 'Thu cửa sổ vừa nội dung']
            assert fit, 'thiếu nút "Thu cửa sổ vừa nội dung"'
            fit[0].invoke()
            root.update_idletasks()
            geo = root.geometry()
            size = geo.split('+')[0]
            w_, h_ = (int(x) for x in size.split('x'))
            assert h_ < 900, f'chiều cao chưa thu: {geo}'
            watch = next(w for w in walk(root) if w.winfo_name() == 'watch_panel')
            assert watch.winfo_height() >= watch.winfo_reqheight(), 'fit clipped THEO DÕI'
            assert h_ == root.minsize()[1], (geo, root.minsize())
            assert w_ <= 1100, 'hidden reserve tab inflated dashboard width'
            print('FIT_WINDOW_OK', geo, 'minimum', root.minsize())
        finally:
            root.destroy()
        sys.exit(0)

    root.after(2600, go)
    original(root, *args)


tk.Tk.mainloop = loop
ns['run_gui'](start_hidden=False)
