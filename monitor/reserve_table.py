import json
import tkinter as tk
from tkinter import ttk, font as tkfont
from datetime import datetime


class ReserveTable(tk.Frame):
    columns = ('model', 'endpoint', 'status', 'ms', 'at', 'note')
    # 'status' chỉ mang LÝ DO lỗi (trạng thái), 'ms' mang con số độ trễ thuần.
    # Trước đây cột status nhét luôn "1568 ms" khi OK nên lặp đúng cột ms — đã tách.
    titles = ('Model', 'Endpoint', 'Trạng thái', 'Độ trễ (ms)', 'Lần thử', 'Ghi chú')
    # Only this column may absorb leftover width; the rest keep the width the
    # autofit computed, so no cell is ever squeezed and a manual drag is
    # detectable (a stretched column changes width without a drag).
    # A real drag moves a column by much more than this tolerance.
    drag_tolerance_px = 12
    stretch_columns = ('model',)

    def __init__(self, parent, preferences=None, **kwargs):
        super().__init__(parent, **kwargs)
        self.preferences = preferences if preferences is not None else {}
        self.items = []
        self.records = {}
        self.sort_column = self.preferences.get('sort_column', 'model')
        if self.sort_column not in self.columns:
            self.sort_column = 'model'
        self.reverse = bool(self.preferences.get('reverse', False))
        self.query = tk.StringVar(value=self.preferences.get('query', ''))
        self.status = tk.StringVar(value=self.preferences.get('status', 'Tất cả'))
        self.endpoint = tk.StringVar(value=self.preferences.get('endpoint', 'Mọi endpoint'))
        bar = ttk.Frame(self)
        bar.pack(fill='x', pady=(0, 6))
        self.optional = tk.BooleanVar(value=self.preferences.get('show_note', False))
        # Grid, not place: the row is laid out by Tk itself, so it is visible
        # immediately and never depends on a <Configure> callback arriving
        # (that dependence once left the whole row invisible on Tk 8.6).
        # Ô Tìm có weight nhưng bị chặn trần nên không nuốt hàng lọc;
        # trước đây nó kéo dài chiếm phần lớn bề ngang rồi đẩy 4 control
        # lọc dốn sang góc phải, tạo khoảng chết trống lớn giữa bảng.
        bar.columnconfigure(1, weight=1, minsize=140)
        bar.columnconfigure(2, weight=0, minsize=0)
        ttk.Label(bar, text='Tìm:').grid(row=0, column=0, sticky='w', padx=(0, 6), pady=3)
        search_entry = ttk.Entry(bar, textvariable=self.query, width=18)
        search_entry.grid(row=0, column=1, sticky='ew', pady=3)
        self.optional_btn = ttk.Checkbutton(bar, text='Ghi chú', variable=self.optional, command=self.toggle_columns)
        self.optional_btn.grid(row=0, column=2, sticky='w', padx=(6, 0), pady=3)
        self.filter_controls = [
            ttk.Combobox(bar, textvariable=self.status, values=('Tất cả', 'Thành công', 'Lỗi', 'Chưa thử'), state='readonly', width=10),
            ttk.Combobox(bar, textvariable=self.endpoint, state='readonly', width=18),
            ttk.Button(bar, text='Xóa lọc', command=self.clear_filters),
            ttk.Button(bar, text='Bố cục mặc định', command=self.reset_layout),
        ]
        self.endpoint_box = self.filter_controls[1]
        for i, ctrl in enumerate(self.filter_controls):
            ctrl.grid(row=0, column=3 + i, sticky='w', padx=(6, 0), pady=3)
        self.bar = bar
        self._narrow = False

        def relayout(event=None):
            """Wide: everything on one row. Narrow: only the filters drop to row 1.
            The Tìm: label, its entry and the note toggle stay put, so the search
            box is never hidden. Default (before any event) is the wide layout."""
            avail = (event.width if event is not None else bar.winfo_width()) or 0
            if avail <= 1:            # not measured yet: leave the wide layout alone
                return
            need_wide = 60 + sum(c.winfo_reqwidth() + 12 for c in self.filter_controls) + 300
            narrow = avail < need_wide
            if narrow == self._narrow:
                return
            self._narrow = narrow
            for i, ctrl in enumerate(self.filter_controls):
                if narrow:
                    ctrl.grid_configure(row=1, column=i, padx=(0, 6))
                else:
                    ctrl.grid_configure(row=0, column=3 + i, padx=(6, 0))

        bar.bind('<Configure>', relayout)
        frame = ttk.Frame(self)
        frame.pack(fill='both', expand=True)
        style = ttk.Style(self)
        from tkinter import font
        table_font = style.lookup('Treeview', 'font') or 'TkDefaultFont'
        lineheight = font.Font(self, font=table_font).metrics('linespace')
        style.configure('Treeview', rowheight=max(26, lineheight + 8))
        self.tree = ttk.Treeview(frame, columns=self.columns, show='headings', selectmode='extended', height=5)
        self.tree.grid(row=0, column=0, sticky='nsew')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        ys = ttk.Scrollbar(frame, orient='vertical', command=self.tree.yview)
        ys.grid(row=0, column=1, sticky='ns')
        xs = ttk.Scrollbar(frame, orient='horizontal', command=self.tree.xview)
        xs.grid(row=1, column=0, sticky='ew')
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.optional = tk.BooleanVar(value=self.preferences.get('show_note', False))
        defaults = {'model': 220, 'endpoint': 175, 'status': 150, 'ms': 85, 'at': 110, 'note': 120}
        caps = {'model': 230, 'endpoint': 235, 'status': 200, 'ms': 88, 'at': 116, 'note': 140}
        floors = {'model': 150, 'endpoint': 130, 'status': 120, 'ms': 66, 'at': 88, 'note': 70}
        self.caps = caps
        self.floors = floors
        self._auto_widths = {}
        saved = self.preferences.get('widths', {})
        for col, title, width in zip(self.columns, self.titles, (defaults[c] for c in self.columns)):
            self.tree.heading(col, text=title, command=lambda c=col: self.sort_by(c))
            want = max(min(int(saved.get(col, width)), caps[col]), floors[col])
            self.tree.column(col, width=want, minwidth=floors[col], stretch=col in self.stretch_columns, anchor='e' if col == 'ms' else 'w')
        self.toggle_columns()
        self.details = tk.StringVar()
        ttk.Label(self, textvariable=self.details, anchor='w', wraplength=950).pack(fill='x', pady=2)
        self.tree.bind('<<TreeviewSelect>>', self.show_detail)
        self.tree.bind('<ButtonRelease-1>', self.remember, add='+')
        for var in (self.query, self.status, self.endpoint):
            var.trace_add('write', lambda *_: self.render(self.items))

    def toggle_columns(self):
        self._apply_columns()

    def _apply_columns(self, has_notes: bool | None = None):
        """Explicit user intent wins: ticking 'Ghi chú' always shows the column, so the
        user can see it and start typing notes. Unticked keeps the table compact."""
        if has_notes is not None:
            self._has_notes = has_notes
        wanted = bool(self.optional.get())
        self.tree.configure(displaycolumns=self.columns if wanted else self.columns[:-1])
        # A hidden column must not keep demanding width in the layout request.
        saved_note = max(min(int(self.preferences.get('widths', {}).get('note', 120)), 130), 70)
        self.tree.column('note', width=saved_note if wanted else 0)
        self.preferences['show_note'] = self.optional.get()

    def identity(self, item):
        return json.dumps([item.get('model', ''), item.get('api_base', '').rstrip('/')], ensure_ascii=False)

    def render(self, items):
        selected = set(self.tree.selection())
        scroll = self.tree.yview()
        self.items = list(items)
        self._apply_columns(any((it.get('note') or '').strip() for it in self.items))
        self.records = {self.identity(item): (i, item) for i, item in enumerate(self.items)}
        self.endpoint_box.configure(values=['Mọi endpoint'] + sorted({x.get('api_base', '') for x in items}))
        q = self.query.get().casefold().strip()
        rows = []
        for iid, (idx, item) in self.records.items():
            probe = item.get('last_probe') or {}
            status = 'Chưa thử' if not probe else ('Thành công' if probe.get('ok') else 'Lỗi')
            if q and q not in (item.get('model', '') + ' ' + item.get('api_base', '') + ' ' + item.get('note', '')).casefold():
                continue
            if self.status.get() not in ('Tất cả', status):
                continue
            if self.endpoint.get() not in ('Mọi endpoint', item.get('api_base', '')):
                continue
            at = probe.get('at', '')
            if isinstance(at, (float, int)):
                at = datetime.fromtimestamp(at).strftime('%d/%m %H:%M:%S')
            # Tách trạng thái khỏi độ trễ: cột status chỉ giữ lý do lỗi/kết quả,
            # cột ms mang con số thuần nên hai cột không lặp nội dung nhau.
            if not probe:
                status_cell = 'Chưa thử'
            elif probe.get('ok'):
                status_cell = 'OK'
            else:
                status_cell = probe.get('text') or status

            # Hiển thị huy hiệu kiểm định Mức 1 đến Mức 5 nếu đã có kết quả
            audit_lvl = item.get('audit_level')
            if audit_lvl:
                status_cell = f"[M{audit_lvl}] {status_cell}"
            values = (item.get('model', ''), item.get('api_base', ''), status_cell, probe.get('ms', ''), at, item.get('note', ''))
            rows.append((iid, values))
        col = self.columns.index(self.sort_column)
        def sort_key(row):
            value = row[1][col]
            if self.sort_column == 'ms':
                try:
                    return float(value)
                except (ValueError, TypeError):
                    return float('inf')
            return str(value).casefold()
        rows.sort(key=sort_key, reverse=self.reverse)
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        for iid, values in rows:
            self.tree.insert('', 'end', iid=iid, values=values)
        self.tree.selection_set([iid for iid in selected if self.tree.exists(iid)])
        if scroll:
            self.tree.yview_moveto(scroll[0])
        self.show_detail()
        self.autofit_columns()
        self.remember()

    def autofit_columns(self):
        """Grow columns to fit their content, bounded by [floors, caps].

        Handing control to the user: as soon as a column width differs from the
        one we set, they dragged it themselves and we stop touching widths.
        """
        if not self.preferences.get('auto_width', True):
            return
        shown = self.columns if self.optional.get() else self.columns[:-1]
        for col in shown:
            if col in self.stretch_columns:
                continue
            try:
                cur = int(self.tree.column(col, 'width'))
            except tk.TclError:
                continue
            recorded = self._auto_widths.get(col)
            if recorded is not None and abs(cur - recorded) > self.drag_tolerance_px:
                # Người dùng thật sự kéo cột: nhường quyền, ghi lại lý do.
                self.preferences['auto_width'] = False
                self.preferences['auto_width_off'] = f"{col}:{recorded}->{cur}"
                return
        fnt = tkfont.Font(self, font=ttk.Style(self).lookup('Treeview', 'font') or 'TkDefaultFont')
        for col in shown:
            idx = self.columns.index(col)
            need = fnt.measure(self.titles[idx])
            for iid in self.tree.get_children():
                vals = self.tree.item(iid, 'values')
                if idx < len(vals):
                    need = max(need, fnt.measure(str(vals[idx])))
            want = max(self.floors[col], min(self.caps[col], need + 18))
            # Cột giãn được phép nới rộng nhưng KHÔNG được co lại dưới cỡ nội dung,
            # nếu không Tk sẽ bóp nó khi cửa sổ hẹp và chữ bị cắt.
            floor = want if col in self.stretch_columns else self.floors[col]
            self.tree.column(col, width=want, minwidth=floor)
            self._auto_widths[col] = want

    def remember(self, event=None):
        self.preferences.update(sort_column=self.sort_column, reverse=self.reverse, query=self.query.get(), status=self.status.get(), endpoint=self.endpoint.get(), widths={c: self.tree.column(c, 'width') for c in self.columns})

    def show_detail(self, event=None):
        picked = self.tree.selection()
        if len(picked) == 1 and picked[0] in self.records:
            item = self.records[picked[0]][1]
            text = item.get('model', '') + ' | ' + item.get('api_base', '')
            if item.get('note'):
                text += ' | ' + item['note']
        else:
            text = f'{len(self.tree.get_children())}/{len(self.items)} model · Đã chọn {len(picked)}'
        self.details.set(text)

    def sort_by(self, column):
        self.reverse = not self.reverse if self.sort_column == column else False
        self.sort_column = column
        self.render(self.items)

    def selected_indices(self):
        return [self.records[iid][0] for iid in self.tree.selection() if iid in self.records]

    def curselection(self):
        return tuple(self.selected_indices())

    def selection_set(self, index):
        if 0 <= index < len(self.items):
            iid = self.identity(self.items[index])
            if self.tree.exists(iid):
                self.tree.selection_set(iid)

    def see(self, index):
        if 0 <= index < len(self.items):
            iid = self.identity(self.items[index])
            if self.tree.exists(iid):
                self.tree.see(iid)

    def bind(self, sequence=None, func=None, add=None):
        return self.tree.bind(sequence, func, add) if hasattr(self, 'tree') else super().bind(sequence, func, add)

    def clear_filters(self):
        self.query.set('')
        self.status.set('Tất cả')
        self.endpoint.set('Mọi endpoint')

    def reset_layout(self):
        self.sort_column = 'model'
        self.reverse = False
        self.optional.set(False)
        self.toggle_columns()
        for col, width in zip(self.columns, (290, 210, 180, 110, 140, 150)):
            self.tree.column(col, width=width)
        self.clear_filters()
        self.remember()
