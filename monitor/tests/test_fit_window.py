import runpy, sys, tkinter as tk
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ns = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'openviking-monitor.pyw'), run_name='fit_test')
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
        root.update_idletasks()
        root.geometry('1200x900')
        root.update_idletasks()
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
        assert w_ <= root.winfo_reqwidth(), (geo, root.winfo_reqwidth())
        assert h_ <= root.winfo_reqheight(), (geo, root.winfo_reqheight())
        print('FIT_WINDOW_OK', geo, 'req', root.winfo_reqwidth(), root.winfo_reqheight())
        root.destroy()
        sys.exit(0)

    root.after(2600, go)
    original(root, *args)


tk.Tk.mainloop = loop
ns['run_gui'](start_hidden=False)
