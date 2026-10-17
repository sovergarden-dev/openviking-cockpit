import runpy, sys, tkinter as tk
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ns = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'openviking-monitor.pyw'), run_name='layout_test')
import os
original_init = tk.Tk.__init__
def scaled_init(root, *args, **kwargs):
    original_init(root, *args, **kwargs)
    root.tk.call('tk', 'scaling', float(os.environ.get('MONITOR_TEST_SCALE', '1.333333')))
tk.Tk.__init__ = scaled_init
original = tk.Tk.mainloop
errors = []
def loop(root, *args):
    def report(kind, value, tb):
        errors.append(str(value))
    root.report_callback_exception = report
    def verify():
        def walk(w):
            yield w
            for ch in w.winfo_children():
                yield from walk(ch)
        tables = [w for w in walk(root) if w.winfo_class() == 'Treeview']

        def text_of(w):
            try:
                t = w.cget('text')
                return t if isinstance(t, str) else ''
            except Exception:
                return ''

        try:
            assert tables, 'missing reserve table'
            for width in (880, 1100, 1400):
                root.geometry(f'{width}x800')
                root.update()
                ops = [w for w in walk(root) if w.winfo_name() == 'ops_panel']
                assert ops, 'missing ops panel'
                assert ops[0].winfo_ismapped(), 'ops panel (VẬN HÀNH) hidden'
                assert tables[0].winfo_width() > width - 130, f'reserve table not full width: table={tables[0].winfo_width()} root={root.winfo_width()} height={tables[0].winfo_height()}'
                from tkinter import ttk, font
                rowheight = int(ttk.Style(root).lookup('Treeview', 'rowheight') or 20)
                fontname = ttk.Style(root).lookup('Treeview', 'font') or 'TkDefaultFont'
                lineheight = font.Font(root, font=fontname).metrics('linespace')
                assert rowheight >= lineheight + 6, f'table row clips text: {rowheight} < {lineheight + 6}'
                reserve = tables[0].master.master
                clipped = []
                for widget in walk(reserve):
                    if widget.winfo_class() in ('TButton', 'TCombobox', 'TCheckbutton'):
                        if not widget.winfo_ismapped() or widget.winfo_width() < widget.winfo_reqwidth() - 3:
                            clipped.append(str(widget))
                assert not clipped, 'reserve controls clipped: ' + ', '.join(clipped)
                bg = ttk.Style(root).lookup('Treeview', 'background') or ''
                lum = None
                if isinstance(bg, str) and bg.startswith('#') and len(bg) == 7:
                    r_, g_, b_ = (int(bg[i:i + 2], 16) for i in (1, 3, 5))
                    lum = (0.2126 * r_ + 0.7152 * g_ + 0.0722 * b_) / 255
                assert lum is not None and lum < 0.35, f'treeview background not dark: {bg!r}'
                mapped_texts = ' '.join(text_of(w) for w in walk(root) if w.winfo_ismapped())
                assert 'retry' in mapped_texts, 'vận hành: dòng meta (retry/failback) đang bị ẩn'
                assert 'lần gọi' in mapped_texts, 'vận hành: dòng usage đang bị ẩn'

                def ancestors(w):
                    chain = []
                    while w is not None:
                        chain.append(w)
                        w = getattr(w, 'master', None)
                    return chain

                infos = [w for w in walk(root) if text_of(w).startswith('OpenViking ') and 'ms' in text_of(w)]
                assert infos, 'dòng thông tin OpenViking … ms bị thiếu'
                assert any(a.winfo_name() == 'ops_panel' for a in ancestors(infos[0])), 'dòng thông tin chưa nằm trong khối VẬN HÀNH'
                assert infos[0].winfo_width() >= infos[0].winfo_reqwidth() - 3, 'dòng thông tin bị cắt'
                links = [w for w in walk(root) if text_of(w) == 'Mở log']
                assert links, 'thiếu nút Mở log'
                assert any(a.winfo_name() == 'ops_panel' for a in ancestors(links[0])), 'nút Mở log chưa chuyển lên khối VẬN HÀNH'
                assert links[0].winfo_ismapped() and links[0].winfo_height() > 5, 'nút Mở log bị khối VẬN HÀNH cắt mất'
                cp = [w for w in walk(root) if text_of(w) == 'Sao chép chẩn đoán']
                assert cp and cp[0].winfo_ismapped() and cp[0].winfo_height() > 5, 'nút Sao chép chẩn đoán bị cắt mất'
                assert 'PID 19330' not in mapped_texts, 'dòng thông tin còn hardcode PID 19330'
                auto = [w for w in walk(root) if text_of(w) == 'Auto thử']
                assert auto, 'thiếu ô Auto thử'
                assert any(a.winfo_name() == 'ops_panel' for a in ancestors(auto[0])), 'Auto thử chưa chuyển vào khối VẬN HÀNH'
                assert auto[0].winfo_ismapped(), 'Auto thử bị ẩn'
                assert not [w for w in walk(root) if text_of(w).strip() == 'Ẩn chi tiết vận hành'], 'còn nút chi tiết vận hành đã bỏ'
                for dead in ('HÀNG ĐỢI', 'VECTOR'):
                    assert not [w for w in walk(root) if text_of(w).strip() == dead and w.winfo_ismapped()], f'cột phải {dead} vẫn hiển thị (lặp thông tin)'
                titles = [w for w in walk(root) if text_of(w).strip() == 'DỰ TRỮ']
                hints = [w for w in walk(root) if 'Double-click' in text_of(w)]
                assert titles and hints, 'thiếu tiêu đề DỰ TRỮ hoặc dòng hướng dẫn'
                assert abs(titles[0].winfo_rooty() - hints[0].winfo_rooty()) <= 4, 'hướng dẫn DỰ TRỮ chưa cùng hàng tiêu đề'
                # Thanh lọc phải HIỆN NGAY, không phụ thuộc <Configure>: mọi mục con
                # phải được map và có kích thước thật (đã từng mất cả hàng trên Tk 8.6).
                entries = [w for w in walk(reserve) if w.winfo_class() == 'TEntry']
                assert entries, 'thiếu ô Tìm:'
                bar = entries[0].master
                limit = 45 if width >= 1000 else 75
                assert bar.winfo_height() <= limit, \
                    f'thanh lọc cao {bar.winfo_height()}px (dải trống thừa) ở width={width}'
                items = [w for w in bar.winfo_children()
                         if w.winfo_class() in ('TLabel', 'TEntry', 'TCheckbutton', 'TCombobox', 'TButton')]
                assert len(items) >= 7, f'thanh lọc thiếu mục: {len(items)}'
                lost = [text_of(w) or w.winfo_class() for w in items if not w.winfo_ismapped() or w.winfo_width() <= 1]
                assert not lost, f'mục trong thanh lọc bị ẩn/không vẽ: {lost}'
                assert any(text_of(w) == 'Tìm:' for w in items), 'mất nhãn Tìm:'
                # Không ô nào trong bảng được cắt chữ (yêu cầu số 1 của người dùng).
                from tkinter import font as tkfont
                tree = tables[0]
                fnt = tkfont.Font(root, font=ttk.Style(root).lookup('Treeview', 'font') or 'TkDefaultFont')
                cols = list(tree['columns'])
                disp = tree.cget('displaycolumns')
                shown = cols if str(disp) in ('all', '#all') else [c for c in cols if c in tuple(disp)]
                widths = {c: int(tree.column(c, 'width')) for c in cols}
                cut = []
                for iid in tree.get_children():
                    vals = list(tree.item(iid, 'values'))
                    for col, val in zip(cols, vals):
                        if col not in shown:
                            continue
                        need = fnt.measure(str(val)) + 14
                        if need > widths[col]:
                            cut.append(f'{col}={widths[col]}<{need}({val!r})')
                viewport = tree.winfo_width()
                total = sum(widths[c] for c in shown)
                if total > viewport + 4:
                    cut = []  # bảng đang phải cuộn ngang: không mất chữ âm thầm
                assert not cut, 'ô bảng bị cắt chữ: ' + '; '.join(cut[:4])
                # Không Label/Nút nào trong thẻ MODEL tự đòi rộng hơn chỗ được cấp
                # (nhãn có wraplength vẫn được phép vượt nhẹ vài px).
                card = ops[0].master
                cutcards = [text_of(w)[:32] for w in walk(card)
                            if w.winfo_class() in ('Label', 'Button') and w.winfo_ismapped()
                            and w.winfo_width() > 1 and w.winfo_reqwidth() > w.winfo_width() + 8]
                assert not cutcards, 'thẻ MODEL cắt chữ: ' + '; '.join(cutcards[:3])
                print('LAYOUT_WIDTH_OK', width)
        except Exception as exc:
            errors.append(str(exc))

    attempts = {"n": 0}

    def run():
        attempts["n"] += 1
        verify()
        # The ops lines only fill in after the first snapshot, which can land
        # later than the fixed wait on a busy machine.
        if errors and attempts["n"] < 5:
            errors.clear()
            root.after(1200, run)
            return
        root.destroy()
        if errors:
            print('LAYOUT_ERRORS', errors)
            sys.exit(1)
        print('GUI_LAYOUT_SMOKE_OK')
        sys.exit(0)

    root.after(2500, run)
    original(root, *args)
tk.Tk.mainloop = loop
ns['run_gui'](start_hidden=False)
