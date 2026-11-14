"""Independent, bounded credential watchlist. All persistence stays in monitor.json."""
import copy
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from conf_gate import model_cache_key
from watch_keys import MAX_WATCHES, WatchBatch, apply_watch_result, upsert_watch


class WatchPanel(tk.Frame):
    def __init__(self, parent, *, state, save, probe, emit, status, sources, colors, font, style_dialog=None, list_models=None, to_spare=None):
        self.colors, self.font = colors, font
        super().__init__(parent, name='watch_panel', bg=colors['surface'],
                         highlightbackground=colors['line'], highlightthickness=1)
        self.state, self.save, self.probe = state, save, probe
        self.emit, self.status, self.sources = emit, status, sources
        self.style_dialog = style_dialog
        self.list_models = list_models
        self.to_spare = to_spare
        self.last_error = ''
        self.batch = WatchBatch()
        self.closed = False
        self._skip_auto_release = False
        self.deadlines = {}
        self.count = tk.StringVar()
        self.detail = tk.StringVar()
        self.auto = tk.BooleanVar(value=bool(state.get('watch_auto_enabled')))
        self.minutes = tk.StringVar(value='1' if state.get('watch_auto_minutes') == 1 else '10')
        head = tk.Frame(self, bg=colors['surface'])
        head.pack(fill='x', padx=12, pady=(8, 4))
        tk.Label(head, text='THEO DÕI', bg=colors['surface'], fg=colors['accent'],
                 font=(font, 8, 'bold')).pack(side='left')
        tk.Label(head, textvariable=self.count, bg=colors['surface'], fg=colors['muted'],
                 font=(font, 8)).pack(side='left', padx=8)
        auto_bar = tk.Frame(head, bg=colors['surface'])
        auto_bar.pack(side='right')
        self.auto_check = tk.Checkbutton(auto_bar, text='Auto thử', variable=self.auto,
                        command=self.save_auto, bg=colors['surface'], fg=colors['ink'],
                        selectcolor=colors['btn'], activebackground=colors['surface'],
                        activeforeground=colors['ink'], font=(font, 8))
        self.auto_check.pack(side='left')
        self.auto_menu = ttk.Combobox(auto_bar, textvariable=self.minutes, values=('1', '10'),
                                     state='readonly', width=3, font=(font, 8))
        self.auto_menu.pack(side='left', padx=(4, 3))
        self.auto_menu.bind('<<ComboboxSelected>>', self.save_auto)
        tk.Label(auto_bar, text='phút', bg=colors['surface'], fg=colors['muted'],
                 font=(font, 8)).pack(side='left')
        tk.Label(self, text='Tối đa 7 key độc lập. Thử có thể tiêu token; không đổi slot OpenViking.',
                 bg=colors['surface'], fg=colors['muted'], font=(font, 8), anchor='w',
                 width=1).pack(fill='x', padx=12, pady=(0, 6))
        table = tk.Frame(self, bg=colors['surface'])
        from tkinter import font as tkfont
        style = ttk.Style(self)
        row_font = (font, 9)
        self.row_font = tkfont.Font(self, font=row_font)
        style.configure('Watch.Treeview', font=row_font,
                        rowheight=tkfont.Font(self, font=row_font).metrics('linespace') + 6)
        style.configure('Watch.Treeview.Heading', font=(font, 8, 'bold'), padding=(4, 2))
        columns = ('alias', 'model', 'status', 'ms', 'last', 'auto')
        self.tree = ttk.Treeview(table, name='watch_tree', columns=columns, show='headings',
                                selectmode='browse', height=7, style='Watch.Treeview')
        for col, title, width in zip(columns, ('Tên gợi nhớ', 'Model thử', 'Kết quả', 'ms', 'Lần thử', 'Auto'),
                                     (142, 180, 184, 62, 106, 88)):
            self.tree.heading(col, text=title)
            if col == 'auto':
                width = max(width, tkfont.Font(self, font=row_font).measure('Chờ tổng') + 14)
            self.tree.column(col, width=width, minwidth=width if col in ('ms', 'last', 'auto') else 80,
                             stretch=col in ('alias', 'model', 'status'))
        vertical = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        horizontal = ttk.Scrollbar(table, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        for tag, color in (('ok', 'ok'), ('bad', 'bad'), ('locked', 'warn'), ('stale', 'warn')):
            self.tree.tag_configure(tag, foreground=colors[color])
        self.tree.bind('<<TreeviewSelect>>', lambda _: self.show_detail())
        self.tree.bind('<Double-Button-1>', self.double_click)
        self.tree.bind('<Delete>', self.delete)
        self.tree.bind('<space>', self.toggle_auto)
        self.tree.bind('<ButtonRelease-1>', self.click_auto)
        detail_label = tk.Label(self, textvariable=self.detail, bg=colors['surface'], fg=colors['muted'],
                                font=(font, 8), anchor='w', width=1)
        actions = tk.Frame(self, bg=colors['surface'])
        actions.pack(side='bottom', fill='x', padx=8, pady=(0, 8))
        detail_label.pack(side='bottom', fill='x', padx=12, pady=4)
        table.pack(fill='both', expand=True, padx=8)
        self.add_btn = self.button(actions, '+ Thêm key', lambda: self.edit(new=True), accent=True)
        self.button(actions, 'Lấy từ…', self.pick_source)
        self.button(actions, '→ Dự trữ', self.copy_to_spare)
        self.button(actions, 'Sửa', self.edit)
        self.button(actions, 'Thử ngay', self.probe_selected)
        self.button(actions, 'Bật/tắt Auto', self.toggle_auto)
        self.button(actions, 'Dừng', self.cancel)
        self.button(actions, 'Xóa', self.delete, right=True)
        self.batch.sync(self.items())
        now, mono = time.time(), time.monotonic()
        for record in self.items():
            due = max(record.get('next_probe_at') or 0, record.get('cooldown_until') or 0)
            self.deadlines[record['id']] = mono + min(3600, max(0, due - now))
        self.render()
        self.bind('<Destroy>', self.on_destroy)

    def button(self, parent, text, command, *, accent=False, right=False):
        c = self.colors
        button = tk.Button(parent, text=text, command=command, bg=c['btn'],
                           fg=c['accent'] if accent else c['ink'], activebackground=c['hover'],
                           activeforeground=c['ink'], relief='flat', font=(self.font, 9),
                           padx=8, pady=3, cursor='hand2')
        button.pack(side='right' if right else 'left', padx=(0, 5))
        return button

    def items(self):
        return self.state.get('watch_keys') or []

    def selected(self):
        selected = self.tree.selection()
        return next((item for item in self.items() if selected and item['id'] == selected[0]), None)

    def copy_to_spare(self):
        record = self.selected()
        if not record:
            self.status('Chọn một dòng trong THEO DÕI để lưu vào Dự trữ.')
            return
        if record.get('_dpapi_locked') or not (record.get('api_key') or '').strip():
            self.status('Key đang bị khóa DPAPI hoặc trống. Hãy mở khóa hoặc nhập key trước khi lưu.')
            return
        if not (record.get('model') or '').strip():
            self.status('Dòng được chọn thiếu tên model.')
            return
        if callable(self.to_spare):
            try:
                _, msg = self.to_spare(record)
                self.status(msg)
            except Exception:
                self.status('Không thể lưu vào Dự trữ')
        else:
            self.status('Chưa kết nối chức năng lưu vào Dự trữ.')

    def persist(self, records, **settings):
        candidate = dict(self.state, watch_keys=records, **settings)
        try:
            self.save(candidate)
        except (RuntimeError, OSError, ValueError):
            self.batch.cancel()
            self.auto.set(False)
            self.last_error = 'Không lưu được THEO DÕI; dữ liệu cũ được giữ nguyên. Auto đã tạm dừng.'
            self.status(self.last_error)
            return False
        self.state.update(watch_keys=records, **settings)
        self.batch.sync(records)
        self.render()
        return True

    def store(self, incoming):
        self.last_error = ''
        previous = next((item for item in self.items() if item['id'] == incoming.get('id')), None)
        try:
            records = upsert_watch(self.items(), incoming)
        except ValueError as exc:
            self.last_error = str(exc)
            self.status(self.last_error)
            return False
        if not self.persist(records):
            return False
        record = next(item for item in records if item['id'] == incoming.get('id')) if incoming.get('id') else records[-1]
        if previous is None or any(previous.get(k) != record.get(k) for k in ('model', 'api_base', 'api_key', 'auto_enabled')):
            self.deadlines[record['id']] = time.monotonic()
        self.tree.selection_set(record['id'])
        self.status('Đã lưu key theo dõi. Không thay đổi slot hoặc ov.conf.')
        return True

    def render(self):
        selected = self.tree.selection()
        existing = set(self.tree.get_children())
        keep = {item['id'] for item in self.items()}
        for identifier in existing - keep:
            self.tree.delete(identifier)
        for item in self.items():
            probe = item.get('last_probe') or {}
            locked = bool(item.get('_dpapi_locked'))
            at = probe.get('at')
            last = time.strftime('%H:%M %d/%m', time.localtime(at)) if at else 'Chưa thử'
            text = 'Khóa DPAPI' if locked else probe.get('text') or 'Chưa thử'
            tag = 'locked' if locked else ('ok' if probe.get('ok') else 'bad') if probe else ''
            if not locked and at and time.time() - at > max(600, int(self.minutes.get()) * 120):
                text = 'Cũ · ' + text
                if probe.get('ok'):
                    tag = 'stale'
            values = (item.get('alias') or 'Không đặt tên', item.get('model'), text,
                      probe.get('ms') if probe.get('ms') is not None else '—', last,
                      ('Bật' if self.auto.get() else 'Chờ tổng') if item.get('auto_enabled') else 'Tắt')
            for index, column in ((3, 'ms'), (4, 'last'), (5, 'auto')):
                needed = self.row_font.measure(str(values[index])) + 14
                if needed > int(self.tree.column(column, 'minwidth')):
                    self.tree.column(column, width=needed, minwidth=needed)
            if item['id'] in existing:
                self.tree.item(item['id'], values=values, tags=(tag,))
            else:
                self.tree.insert('', 'end', iid=item['id'], values=values, tags=(tag,))
        if selected and selected[0] in keep:
            self.tree.selection_set(selected[0])
        self.count.set(f'{len(keep)}/{MAX_WATCHES}')
        self.add_btn.configure(state='disabled' if len(keep) >= MAX_WATCHES else 'normal')
        self.show_detail()

    def show_detail(self):
        record = self.selected()
        if not record:
            self.detail.set('Chọn một dòng. Space bật/tắt Auto; double-click để sửa.' if self.items()
                            else 'Chưa có key. Thêm mới hoặc sao chép độc lập từ Dự trữ / slot.')
            return
        reason = record.get('auto_disabled_reason') or ''
        remaining = max(0, self.deadlines.get(record['id'], 0) - time.monotonic())
        schedule = (f' · thử sau {int(remaining) + 1}s' if remaining else ' · đến lịch') if record.get('auto_enabled') and self.auto.get() else ''
        if record.get('auto_enabled') and not self.auto.get():
            schedule = ' · Chờ Auto tổng'
        self.detail.set(f"{record.get('api_base')}" + (f' · {reason}' if reason else schedule))

    def toggle_auto(self, _event=None):
        record = self.selected()
        if not record:
            self.status('Chọn key theo dõi để bật/tắt Auto.')
            return 'break'
        if record.get('_dpapi_locked'):
            self.status('Key đang khóa DPAPI. Nhập lại key trước khi bật Auto.')
            return 'break'
        self.store(dict(record, auto_enabled=not record.get('auto_enabled')))
        return 'break'

    def double_click(self, event):
        if self.tree.identify_region(event.x, event.y) != 'cell':
            return 'break'
        identifier = self.tree.identify_row(event.y)
        if not identifier:
            return 'break'
        self.tree.selection_set(identifier)
        if self.tree.identify_column(event.x) == '#6':
            self._skip_auto_release = True
        else:
            self.edit()
        return 'break'

    def click_auto(self, event):
        if self._skip_auto_release:
            self._skip_auto_release = False
            return 'break'
        if self.tree.identify_region(event.x, event.y) == 'cell' and self.tree.identify_column(event.x) == '#6':
            self.toggle_auto()

    def save_auto(self, _event=None):
        enabled, minutes = bool(self.auto.get()), int(self.minutes.get())
        if self.persist(copy.deepcopy(self.items()), watch_auto_enabled=enabled, watch_auto_minutes=minutes):
            if not enabled:
                self.batch.cancel()
            self.status('Auto THEO DÕI đã bật; chỉ thử những dòng bật Auto.' if enabled else 'Đã tắt Auto THEO DÕI. Request đã gửi vẫn có thể hoàn tất.')
        else:
            self.minutes.set(str(self.state.get('watch_auto_minutes') or 10))

    def tick(self):
        if self.closed:
            return
        self.render()
        if not self.auto.get() or self.batch.busy:
            return
        now = time.monotonic()
        due = [item for item in self.items() if item.get('auto_enabled') and
               now >= self.deadlines.get(item['id'], 0)]
        self.batch.start(due, self.probe, self.emit, auto=True)
        self.show_detail()

    def probe_selected(self):
        record = self.selected()
        if not record:
            self.status('Chọn key theo dõi để thử.')
        elif self.batch.busy:
            self.status('Đang thử. Dừng để bỏ các request chưa gửi.')
        elif self.batch.start([record], self.probe, self.emit):
            self.status('Đang thử key đã chọn; timeout 20 giây, tối đa 64 output token.')
        else:
            self.status('Key rỗng hoặc đang khóa DPAPI; không gửi request.')

    def event(self, event):
        if self.closed:
            return
        if event[0] == 'watch_done':
            self.batch.complete(event[1])
            return
        if event[0] != 'watch_result':
            return
        _, run_id, identifier, revision, result = event
        if not self.batch.accepts(run_id, identifier, revision):
            return
        records = copy.deepcopy(self.items())
        for index, record in enumerate(records):
            if record['id'] != identifier:
                continue
            updated = apply_watch_result(record, result, interval=int(self.minutes.get()) * 60)
            records[index] = updated
            if self.persist(records):
                delay = max(0, updated['next_probe_at'] - updated['last_probe']['at'])
                self.deadlines[identifier] = time.monotonic() + delay
                self.show_detail()
                old = record.get('last_probe') or {}
                latest = updated['last_probe']
                if (old.get('ok'), old.get('text')) != (latest['ok'], latest['text']):
                    self.status('THEO DÕI · ' + latest['text'] + (' · Auto tự tắt' if updated['auto_disabled_reason'] else ''))
            break

    def cancel(self):
        self.batch.cancel()
        self.status('Đã dừng lô thử. Request đang gửi không thể thu hồi; kết quả trễ được bỏ.')

    def delete(self, _event=None):
        record = self.selected()
        if record and messagebox.askyesno('Xóa key theo dõi', 'Xóa dòng đã chọn khỏi THEO DÕI? Không ảnh hưởng Dự trữ hoặc slot.', parent=self):
            if self.persist([copy.deepcopy(item) for item in self.items() if item['id'] != record['id']]):
                self.deadlines.pop(record['id'], None)
                self.status('Đã xóa key theo dõi. Dự trữ và slot giữ nguyên.')
        return 'break'

    def edit(self, *, new=False, source=None):
        record = None if new else self.selected()
        if not new and not record:
            self.status('Chọn key theo dõi để sửa.')
            return
        if new and len(self.items()) >= MAX_WATCHES:
            self.status('Tối đa 7 key theo dõi.')
            return
        initial = source or record or {}
        win = tk.Toplevel(self)
        win.title('Thêm key theo dõi' if new else 'Sửa key theo dõi')
        win.configure(bg=self.colors['surface'])
        win.transient(self.winfo_toplevel())
        win.resizable(False, False)
        win.grab_set()
        win.bind('<Escape>', lambda _: win.destroy())
        fields = {}
        model_box = None
        for name, label in (('alias', 'Tên gợi nhớ'), ('model', 'Model dùng để thử'),
                            ('api_base', 'Base URL (kết thúc bằng /v1)'), ('api_key', 'API key')):
            tk.Label(win, text=label, bg=self.colors['surface'], fg=self.colors['muted'],
                     font=(self.font, 9), anchor='w').pack(fill='x', padx=16, pady=(9, 3))
            fields[name] = tk.StringVar(value=initial.get(name) or '')
            if name == 'model':
                model_row = tk.Frame(win, bg=self.colors['surface'])
                model_row.pack(fill='x', padx=16)
                model_box = ttk.Combobox(model_row, name='watch_model', textvariable=fields['model'],
                                         style='Ov.TCombobox', state='normal')
                model_box.pack(side='left', fill='x', expand=True, ipady=2)
                initial_models = []
                curr_model = (initial.get('model') or '').strip()
                if curr_model:
                    initial_models.append(curr_model)
                init_base = (initial.get('api_base') or '').strip()
                init_key = (initial.get('api_key') or '').strip()
                if init_base and init_key:
                    init_ck = model_cache_key(init_base, init_key)
                    cached_ids = (self.state.get('model_lists') or {}).get(init_ck) or []
                    for mid in cached_ids:
                        if mid and mid not in initial_models:
                            initial_models.append(str(mid))
                for _, s_item in self.sources():
                    sm = (s_item.get('model') or '').strip()
                    if sm and sm not in initial_models:
                        initial_models.append(sm)
                model_box['values'] = tuple(initial_models)
                model_box.configure(height=min(8, max(4, len(initial_models))))

                def fetch_models():
                    base = fields['api_base'].get().strip()
                    key = fields['api_key'].get().strip()
                    if not base:
                        error.set('Thiếu Base URL để lấy danh sách model.')
                        return
                    if not key:
                        error.set('Thiếu API key (hoặc key bị khóa DPAPI). Hãy nhập key để lấy danh sách.')
                        return
                    error.set('Đang lấy danh sách model…')
                    refresh_btn.configure(state='disabled')
                    box = {}
                    deadline = time.monotonic() + 25.0

                    def work():
                        try:
                            if callable(self.list_models):
                                res = self.list_models(base, key)
                            else:
                                res = {'ok': False, 'ids': [], 'text': 'Chưa kết nối list_models'}
                        except Exception:
                            res = {'ok': False, 'ids': [], 'text': 'Lỗi kết nối tới endpoint'}
                        box['res'] = res

                    def poll():
                        try:
                            if not win.winfo_exists() or getattr(self, 'closed', False):
                                return
                        except Exception:
                            return
                        if 'res' not in box:
                            if time.monotonic() > deadline:
                                refresh_btn.configure(state='normal')
                                error.set('Hết thời gian lấy danh sách model')
                                return
                            win.after(40, poll)
                            return
                        refresh_btn.configure(state='normal')
                        current_base = fields['api_base'].get().strip()
                        current_key = fields['api_key'].get().strip()
                        is_stale = (current_base != base or current_key != key)
                        res = box.get('res') or {}
                        ids = res.get('ids') or []
                        if ids:
                            cache_k = model_cache_key(base, key)
                            updated = dict(self.state.get('model_lists') or {}, **{cache_k: list(ids)})
                            self.state['model_lists'] = updated
                            if callable(self.save):
                                try:
                                    self.save(dict(self.state, model_lists=updated))
                                except Exception:
                                    self.status('Không lưu được cache model_lists')
                            if is_stale:
                                error.set('Base URL hoặc API key đã đổi trong khi tải; bấm Lấy list lại')
                                return
                            current_val = fields['model'].get().strip()
                            combo_vals = list(ids)
                            if current_val and current_val not in combo_vals:
                                combo_vals.insert(0, current_val)
                            model_box['values'] = tuple(combo_vals)
                            model_box.configure(height=min(8, max(4, len(combo_vals))))
                            error.set(f"Đã lấy {len(ids)} model · chọn trong danh sách sổ xuống")
                        else:
                            if is_stale:
                                error.set('Base URL hoặc API key đã đổi trong khi tải; bấm Lấy list lại')
                            else:
                                error.set(res.get('text') or 'Không lấy được danh sách model')

                    threading.Thread(target=work, daemon=True).start()
                    win.after(40, poll)

                refresh_btn = self.button(model_row, 'Lấy list', fetch_models, right=True)
            else:
                ttk.Entry(win, name='watch_' + name, textvariable=fields[name], width=52,
                          show='•' if name == 'api_key' else '').pack(fill='x', padx=16)
        error = tk.StringVar(value='Key được mã hóa DPAPI. Không kế thừa key từ endpoint khác.')
        tk.Label(win, textvariable=error, bg=self.colors['surface'], fg=self.colors['warn'],
                 font=(self.font, 8), wraplength=440, justify='left').pack(fill='x', padx=16, pady=10)
        buttons = tk.Frame(win, bg=self.colors['surface'])
        buttons.pack(fill='x', padx=16, pady=(0, 12))
        def save():
            incoming = dict({'id': record['id']} if record else {},
                            **{name: value.get() for name, value in fields.items()})
            if self.store(incoming):
                win.destroy()
            else:
                error.set(self.last_error)
        self.button(buttons, 'Lưu', save, accent=True)
        self.button(buttons, 'Hủy', win.destroy, right=True)
        win.update_idletasks()
        root = self.winfo_toplevel()
        x = max(0, min(root.winfo_rootx() + 30, root.winfo_screenwidth() - win.winfo_reqwidth() - 30))
        y = max(0, min(root.winfo_rooty() + 60, root.winfo_screenheight() - win.winfo_reqheight() - 70))
        win.geometry(f'+{x}+{y}')
        if self.style_dialog:
            self.style_dialog(win)

    def pick_source(self):
        if len(self.items()) >= MAX_WATCHES:
            self.status('Tối đa 7 key theo dõi; xóa một dòng trước khi thêm.')
            return
        sources = list(self.sources())
        win = tk.Toplevel(self)
        win.title('Sao chép vào THEO DÕI')
        win.configure(bg=self.colors['surface'])
        win.transient(self.winfo_toplevel())
        win.grab_set()
        win.bind('<Escape>', lambda _: win.destroy())
        tk.Label(win, text='Chọn bản gốc. Key được sao chép độc lập; không đổi slot hoặc Dự trữ.',
                 bg=self.colors['surface'], fg=self.colors['muted'], font=(self.font, 9)).pack(padx=12, pady=10)
        tree = ttk.Treeview(win, columns=('source', 'model', 'endpoint'), show='headings', selectmode='browse', height=10)
        for col, title, width in (('source', 'Nguồn', 110), ('model', 'Model', 220), ('endpoint', 'Endpoint', 240)):
            tree.heading(col, text=title)
            tree.column(col, width=width)
        tree.pack(fill='both', expand=True, padx=12)
        for index, (label, item) in enumerate(sources):
            tree.insert('', 'end', iid=str(index), values=(label, item.get('model'), item.get('api_base')))
        error = tk.StringVar()
        tk.Label(win, textvariable=error, bg=self.colors['surface'], fg=self.colors['warn'],
                 font=(self.font, 9), wraplength=560, justify='left').pack(fill='x', padx=12, pady=(6, 0))
        def choose():
            selection = tree.selection()
            if not selection:
                return
            _, item = sources[int(selection[0])]
            if item.get('_dpapi_locked') or not item.get('api_key'):
                error.set('Bản gốc không có key đọc được. Không kế thừa key ngầm.')
                self.status(error.get())
                return
            source = {name: item.get(name) or '' for name in ('model', 'api_base', 'api_key')}
            win.destroy()
            self.edit(new=True, source=source)
        buttons = tk.Frame(win, bg=self.colors['surface'])
        buttons.pack(fill='x', padx=12, pady=10)
        self.button(buttons, 'Sao chép và sửa', choose, accent=True)
        self.button(buttons, 'Hủy', win.destroy, right=True)
        win.update_idletasks()
        root = self.winfo_toplevel()
        x = root.winfo_rootx() + max(0, (root.winfo_width() - win.winfo_reqwidth()) // 2)
        y = root.winfo_rooty() + max(0, (root.winfo_height() - win.winfo_reqheight()) // 2)
        x = max(0, min(x, root.winfo_screenwidth() - win.winfo_reqwidth() - 30))
        y = max(0, min(y, root.winfo_screenheight() - win.winfo_reqheight() - 70))
        win.geometry(f'+{x}+{y}')
        if self.style_dialog:
            self.style_dialog(win)

    def on_destroy(self, event):
        if event.widget is self:
            self.close()

    def close(self):
        self.closed = True
        self.batch.cancel()
