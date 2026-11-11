import runpy, sys, tkinter as tk, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TEST_SCALE = float(os.environ.get('MONITOR_TEST_SCALE', '1.333333'))
original_init = tk.Tk.__init__
def scaled_init(root, *args, **kwargs):
    original_init(root, *args, **kwargs)
    root.tk.call('tk', 'scaling', TEST_SCALE)
tk.Tk.__init__ = scaled_init
ns = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'openviking-monitor.pyw'), run_name='layout_test')
GUI = ns['run_gui'].__globals__
fixture_slots = [
    {'index': i, 'id': f'layout-fixture-{i}', 'model': f'fixture/model-{i}',
     'api_base': 'https://provider-fixture.invalid/v1', 'api_key': 'synthetic-key'}
    for i in range(4)
]
fixture_conf = {
    'primary': fixture_slots[0]['model'], 'api_base': fixture_slots[0]['api_base'],
    'api_key': 'synthetic-key', 'thinking': True, 'max_retries': 2,
    'failback_timeout_seconds': 3600, 'failback_request_count': 2147483647,
    'slots': fixture_slots,
}
GUI['load_state'] = lambda: {
    'geometry': '1020x640', 'geometry_autofit': True, 'manual_split': False,
    'reserve_split': 0, 'spare_models': [
        {'model': f'fixture/spare-{i}',
         'api_base': 'https://provider-fixture.invalid/v1/compatible/chat/completions',
         'api_key': 'synthetic-key',
         'note': 'synthetic long endpoint and probe status for DPI clipping validation',
         'last_probe': {'ok': False, 'text': 'auth-or-quota · HTTP 401: fixture credential rejected', 'ms': 12345, 'at': 1760000000}}
        for i in range(4)
    ], 'model_lists': {},
    'reserve_layout': {}, 'probe': {}, 'auto_probe_enabled': False,
    'watch_keys': [dict(id=f'layout-watch-{i}', rev=1, alias=f'Key {i + 1}', model=f'fixture/watch-{i}',
                        api_base='https://fixture.invalid/v1', api_key='synthetic-key', auto_enabled=False)
                   for i in range(7)],
}
GUI['save_state'] = lambda _state: None
GUI['read_ov_conf'] = lambda resolve_env=False: fixture_conf
GUI['collect'] = lambda include_ready=False: {
    'ts': 1, 'elapsed_ms': 1, 'health_code': 200, 'health': {'healthy': True, 'version': 'fixture'},
    'ov_up': True, 'version': 'fixture', 'ollama_up': True, 'gateway_up': True, 'gateway_http': True,
    'queue': {'pending': 3, 'errors': 2, 'in_progress': 1},
    'vectors': {'vectors': 12345678, 'indexes': 12},
    'usage': {'all': [{'model': 'fixture/model-0', 'calls': 1234}]},
    'retrieval': {'queries': 12345, 'score': 0.913, 'latency_ms': 456, 'zero_rate': '2%'}, 'conf': fixture_conf,
    'listeners': {'ov': [{'pid': '4242', 'addr': '127.0.0.1:19330'}], 'ollama': [], 'gateway': []},
    'task': {'status': 'Ready', 'last_result': '0'}, 'issues': [], 'failover': False, 'active': 0,
    'live': {'index': 0, 'n': 4, 'manual_hold': False, 'credential_ids': [slot['id'] for slot in fixture_slots]},
    'failover_detail': '', 'ov_down_since': None, 'ov_procs': None,
}
original = tk.Tk.mainloop
errors = []
startup_errors = []

def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def text_of(widget):
    try:
        value = widget.cget('text')
        return value if isinstance(value, str) else ''
    except Exception:
        return ''

def loop(root, *args):
    def report(kind, value, tb):
        startup_errors.append(f'{kind.__name__}: {value}')
    root.report_callback_exception = report

    def capture_startup_fit():
        try:
            root.update_idletasks()
            widgets = {}
            for widget in walk(root):
                if widget.winfo_name() == 'ops_panel':
                    widgets['ops'] = widget
                elif text_of(widget) == '+ Thêm dự phòng':
                    widgets['add'] = widget
                elif widget.winfo_class() == 'TNotebook':
                    widgets['tabs'] = widget
            assert {'ops', 'add', 'tabs'} <= widgets.keys(), 'startup layout is incomplete'
            geometry = root.winfo_geometry()
            size = geometry.split('+')[0]
            _, height = (int(value) for value in size.split('x'))
            assert height > 640, f'startup auto-fit did not expand default height: {geometry}'
            upper_pane = widgets['ops'].master.master.master
            widgets['tabs'].update_idletasks()
            checks = (("upper", upper_pane, 0), ("ops", widgets['ops'], 0), ("add", widgets['add'], 2))
            failures = [f'{name}={widget.winfo_height()}<{widget.winfo_reqheight()}'
                        for name, widget, tolerance in checks
                        if widget.winfo_height() < widget.winfo_reqheight() - tolerance]
            assert not failures, f'startup auto-fit clipping {geometry}: {failures}'
        except Exception as exc:
            startup_errors.append(f'startup fit: {exc}')

    root.after(6500, capture_startup_fit)

    def verify():
        tabs = next(widget for widget in walk(root) if widget.winfo_class() == 'TNotebook')
        tables = [widget for widget in walk(root) if widget.winfo_class() == 'Treeview' and widget.winfo_name() != 'watch_tree']

        layout_sizes = ((880, 800), (880, 560), (996, 960), (1020, 640), (1100, 800), (1400, 800))
        try:
            startup_ops = [w for w in walk(root) if w.winfo_name() == 'ops_panel']
            startup_upper = [w for w in walk(root) if w.winfo_name() == 'overview']
            startup_add = [w for w in walk(root) if text_of(w) == '+ Thêm dự phòng']
            assert startup_ops and startup_upper and startup_add, 'startup layout is incomplete'
            for width, requested_height in layout_sizes:
                tabs.select(0)
                root.geometry(f'{width}x{requested_height}')
                root.update()
                actual_height = root.winfo_height()
                assert actual_height >= requested_height, (
                    f'geometry fell below request after content minimum: request={width}x{requested_height}, '
                    f'actual={root.winfo_geometry()}'
                )
                upper_pane = startup_ops[0].master.master.master
                assert upper_pane.winfo_height() >= upper_pane.winfo_reqheight(), (
                    f'upper pane vertically clipped: scale={TEST_SCALE} geometry={root.winfo_geometry()} '
                    f'{upper_pane.winfo_height()}<{upper_pane.winfo_reqheight()}'
                )
                ops = [w for w in walk(root) if w.winfo_name() == 'ops_panel']
                assert ops and ops[0].winfo_height() >= ops[0].winfo_reqheight(), (
                    f'ops panel vertically clipped: scale={TEST_SCALE} geometry={root.winfo_geometry()} '
                    f'{ops[0].winfo_height()}<{ops[0].winfo_reqheight()}'
                )
                controls = [w for w in walk(root) if text_of(w) == '+ Thêm dự phòng']
                assert controls and controls[0].winfo_height() >= controls[0].winfo_reqheight() - 2, (
                    f'add control vertically clipped: scale={TEST_SCALE} geometry={root.winfo_geometry()}'
                )
                assert ops[0].winfo_ismapped(), 'ops panel (VẬN HÀNH) hidden'

                from tkinter import ttk, font
                rowheight = int(ttk.Style(root).lookup('Treeview', 'rowheight') or 20)
                fontname = ttk.Style(root).lookup('Treeview', 'font') or 'TkDefaultFont'
                lineheight = font.Font(root, font=fontname).metrics('linespace')
                assert rowheight >= lineheight + 6, f'table row clips text: {rowheight} < {lineheight + 6}'
                reserve = tables[0].master.master
                clipped = []
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
                assert any(a.winfo_name() == 'watch_panel' for a in ancestors(auto[0])), 'Auto thử phải nằm trong THEO DÕI'
                assert auto[0].winfo_ismapped(), (
                    f'Auto thử bị ẩn: scale={TEST_SCALE} root={root.winfo_geometry()} '
                    f'ops={ops[0].winfo_geometry()} req={ops[0].winfo_reqheight()} '

                    f'ops_children={[(w.winfo_class(), text_of(w)[:36], w.winfo_reqheight(), w.winfo_height()) for w in walk(ops[0]) if w is not ops[0]]}'
                )
                watch = next(w for w in walk(root) if w.winfo_name() == 'watch_panel')
                watch_tree = watch.tree
                watch_rows = watch_tree.get_children()
                assert len(watch_rows) == 7
                visible = [row for row in watch_rows if watch_tree.bbox(row)
                           and sum(watch_tree.bbox(row)[1::2]) <= watch_tree.winfo_height() - 2]
                assert len(visible) >= 3, (f'THEO DÕI chỉ hiện {len(visible)} hàng: {watch_tree.winfo_geometry()} '
                                           f'root={root.winfo_geometry()} upper={upper_pane.winfo_geometry()} '
                                           f'ops={ops[0].winfo_geometry()} watch={watch.winfo_geometry()} '
                                           f'rows={[(w.winfo_height(), w.winfo_reqheight(), text_of(w)) for w in walk(upper_pane) if w.winfo_class() == "Button"]}')

                watch_tree.see(watch_rows[-1])
                root.update_idletasks()
                assert watch_tree.bbox(watch_rows[-1]), 'Không cuộn tới được key thứ 7'
                watch_tree.yview_moveto(0)
                lost_watch = [text_of(w) for w in walk(watch) if w.winfo_class() in ('Button', 'Checkbutton', 'TCombobox')
                              and (not w.winfo_ismapped() or w.winfo_width() + 3 < w.winfo_reqwidth())]
                assert not lost_watch, (f'THEO DÕI cắt điều khiển: {lost_watch}; root={root.winfo_geometry()} '
                                        f'watch={watch.winfo_geometry()} req={watch.winfo_reqheight()} '
                                        f'children={[(w.winfo_class(), w.winfo_geometry(), w.winfo_reqheight()) for w in watch.winfo_children()]}')
                assert not [w for w in walk(root) if text_of(w).strip() == 'Ẩn chi tiết vận hành'], 'còn nút chi tiết vận hành đã bỏ'
                for dead in ('HÀNG ĐỢI', 'VECTOR'):
                    assert not [w for w in walk(root) if text_of(w).strip() == dead and w.winfo_ismapped()], f'cột phải {dead} vẫn hiển thị (lặp thông tin)'
                card = ops[0].master
                cutcards = [text_of(w)[:32] for w in walk(card)
                            if w.winfo_class() in ('Label', 'Button') and w.winfo_ismapped()
                            and w.winfo_width() > 1 and w.winfo_reqwidth() > w.winfo_width() + 8]
                assert not cutcards, 'thẻ MODEL cắt chữ: ' + '; '.join(cutcards[:3])
                model_names = [w for w in walk(card) if w.winfo_class() == 'Button' and 'provider-fixture.invalid' in text_of(w)]
                assert len(model_names) == 4
                for widget in model_names:
                    measured = font.Font(root, font=widget.cget('font')).measure(text_of(widget)) + 8
                    wrap = widget.winfo_pixels(widget.cget('wraplength'))
                    assert measured <= widget.winfo_width() or 0 < wrap <= widget.winfo_width(), 'tên model bị cắt chữ'
                tabs.select(1)
                root.update()
                assert tables[0].winfo_width() > width - 130, 'reserve table not full width'
                assert tables[0].winfo_height() > 150, 'reserve tab lost vertical space'
                for widget in walk(reserve.master):
                    if widget.winfo_class() in ('Button', 'TButton', 'TCombobox', 'TCheckbutton'):
                        if not widget.winfo_ismapped() or widget.winfo_width() < widget.winfo_reqwidth() - 3:
                            clipped.append(str(widget))
                assert not clipped, 'reserve controls clipped: ' + ', '.join(clipped)
                titles = [w for w in walk(root) if text_of(w).strip() == 'DỰ TRỮ']
                hints = [w for w in walk(root) if 'Double-click' in text_of(w)]
                assert titles and hints, 'thiếu tiêu đề DỰ TRỮ hoặc dòng hướng dẫn'
                assert abs(titles[0].winfo_rooty() - hints[0].winfo_rooty()) <= 4, 'hướng dẫn DỰ TRỮ chưa cùng hàng tiêu đề'
                # Thanh lọc phải HIỆN NGAY, không phụ thuộc <Configure>: mọi mục con
                # phải được map và có kích thước thật (đã từng mất cả hàng trên Tk 8.6).
                entries = [w for w in walk(reserve) if w.winfo_class() == 'TEntry']
                assert entries, 'thiếu ô Tìm:'
                bar = entries[0].master
                limit = round((60 if width >= 1000 else 75) * TEST_SCALE / (4.0 / 3.0))
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
                    scrollbars = [
                        widget for widget in tree.master.winfo_children()
                        if widget.winfo_class().endswith("Scrollbar")
                        and str(widget.cget("orient")).casefold().startswith("horizontal")
                    ]
                    assert scrollbars and scrollbars[0].winfo_ismapped(), (
                        f'nội dung tràn nhưng thiếu thanh cuộn ngang: total={total} viewport={viewport} '
                        f'xview={tree.xview()}'
                    )
                    assert tree.xview()[1] < 0.999, f'nội dung tràn nhưng xview không báo vùng cuộn: {tree.xview()}'
                assert not cut, 'ô bảng bị cắt chữ dù có thể cuộn ngang: ' + '; '.join(cut[:4])

        except Exception as exc:
            errors.append(str(exc))

    def run():
        verify()
        if startup_errors:
            errors.extend(startup_errors)
        root.destroy()
        if errors:
            print('LAYOUT_ERRORS', errors)
            sys.exit(1)
        print('GUI_LAYOUT_SMOKE_OK')
        sys.exit(0)

    root.after(7000, run)
    original(root, *args)
tk.Tk.mainloop = loop
ns['run_gui'](start_hidden=False)
