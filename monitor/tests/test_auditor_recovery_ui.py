"""Headless Tk contract tests; worker/UI ownership is checked explicitly."""
import sys
import types
from unittest.mock import Mock, patch

import pytest
from test_auditor_recovery import psa, isolated, BASE, KEY, fake_provider


class Harness:
    def __init__(self):
        self.worker = False
        self.widgets = []
        self.threads = []
        self.pending = []
        owner = self
        class Widget:
            def __init__(self, parent=None, **kwargs):
                owner.check()
                self.parent = parent
                self.kwargs = kwargs
                self.bindings = {}
                self.protocols = {}
                self.dead = False
                self.value = kwargs.get('value', '')
                owner.widgets.append(self)
            def __getattr__(self, name):
                def call(*args, **kwargs):
                    owner.check()
                    if name == 'winfo_exists':
                        return not self.dead
                    if name in ('configure','config'):
                        self.kwargs.update(kwargs)
                    if name == 'set':
                        self.value = args[0]
                    if name == 'get':
                        return self.value
                    if name == 'after':
                        owner.pending.append((self,args[1]))
                        return str(len(owner.pending))
                    if name == 'bind':
                        self.bindings[args[0]] = args[1]
                    if name == 'protocol':
                        self.protocols[args[0]] = args[1]
                    if name == 'insert':
                        self.value += str(args[-1])
                    if name == 'destroy':
                        self.dead = True
                        if '<Destroy>' in self.bindings:
                            self.bindings['<Destroy>'](types.SimpleNamespace(widget=self))
                return call
        class Thread:
            def __init__(self, target, daemon=False):
                self.target = target
                self.daemon = daemon
                owner.threads.append(self)
            def start(self):
                pass
            def run(self):
                owner.worker = True
                try:
                    self.target()
                finally:
                    owner.worker = False
        self.Thread = Thread
        self.tk = types.ModuleType('tkinter')
        for name in ('Toplevel','Frame','Label','Button','StringVar','Text'):
            setattr(self.tk,name,Widget)
        self.tk.TclError = RuntimeError
        self.ttk = types.ModuleType('tkinter.ttk')
        self.ttk.Notebook = self.ttk.Treeview = Widget
        self.tk.ttk = self.ttk
        self.root = Widget()

    def check(self):
        assert not self.worker, 'Tk touched from worker'

    def pump(self):
        pending, self.pending = self.pending, []
        for widget, callback in pending:
            if not widget.dead:
                callback()

    def window(self):
        return next(w for w in self.widgets if w.parent is self.root)

    def click(self, text):
        next(w for w in self.widgets if w.kwargs.get('text') == text).kwargs['command']()

    def text(self):
        return str([(w.kwargs,w.value) for w in self.widgets])


@pytest.fixture
def gui():
    harness = Harness()
    with patch.dict(sys.modules, {'tkinter':harness.tk, 'tkinter.ttk':harness.ttk}), patch.object(psa.threading, 'Thread', harness.Thread):
        yield harness
    assert not psa._AUDIT_UI_LOCK.locked()


def launch(gui, **kwargs):
    psa.launch_security_audit_ui(gui.root, BASE, KEY, 'synthetic', **kwargs)


def test_worker_uses_queue_and_saved_completion_runs_once_on_main(gui):
    callback = Mock(side_effect=lambda report: gui.check())
    launch(gui, on_complete=callback)
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider):
        gui.threads[0].run()
    callback.assert_not_called()
    gui.pump()
    callback.assert_called_once()
    assert callback.call_args.args[0]['saved_report_file']
    assert callback.call_args.args[0]['verdict']['memory_permitted']
    gui.pump()
    callback.assert_called_once()


def test_single_flight_rejects_second_worker_visibly(gui):
    launch(gui)
    launch(gui)
    assert len(gui.threads) == 1
    assert 'AUDIT_ALREADY_RUNNING' in gui.text()
    gui.window().protocols['WM_DELETE_WINDOW']()
    gui.threads[0].run()


@pytest.mark.parametrize('close', ['protocol','destroy'])
def test_close_cancels_and_suppresses_ui_writes(gui, close):
    callback = Mock()
    launch(gui,on_complete=callback)
    win = gui.window()
    if close == 'protocol':
        win.protocols['WM_DELETE_WINDOW']()
    else:
        win.destroy()
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider) as transport:
        gui.threads[0].run()
    transport.assert_not_called()
    before = gui.text()
    gui.pump()
    assert gui.text() == before
    callback.assert_not_called()


def test_worker_exception_is_visible_sanitized_and_releases_lock(gui):
    callback = Mock()
    launch(gui,on_complete=callback)
    with patch.object(psa, 'audit_provider', side_effect=RuntimeError(KEY)):
        gui.threads[0].run()
    gui.pump()
    assert 'AUDIT_FAILED' in gui.text()
    assert KEY not in gui.text()
    callback.assert_not_called()


def test_failed_save_never_calls_completion(gui):
    callback = Mock()
    launch(gui,on_complete=callback)
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider), patch.object(psa.os, 'replace', side_effect=OSError(KEY)):
        gui.threads[0].run()
    gui.pump()
    assert 'REPORT_SAVE_FAILED' in gui.text()
    callback.assert_not_called()


def test_cancel_after_worker_before_publication_removes_permit(gui):
    callback = Mock()
    launch(gui,on_complete=callback)
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider):
        gui.threads[0].run()
    gui.click('Dừng')
    gui.pump()
    report = psa.get_latest_audit_report(BASE,'synthetic',api_key=KEY)
    assert not report or not report['verdict']['memory_permitted']
    callback.assert_not_called()


def test_closed_after_worker_does_not_leave_trusted_pass(gui):
    launch(gui)
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider):
        gui.threads[0].run()
    gui.window().destroy()
    gui.pump()
    assert psa.get_latest_audit_report(BASE,'synthetic',api_key=KEY) is None


def test_cached_display_revalidates_without_worker_or_completion(gui):
    with patch.object(psa, 'execute_bounded_http', side_effect=fake_provider):
        report = psa.audit_provider(BASE,KEY,'synthetic')
    callback = Mock()
    launch(gui,cached_report=report,on_complete=callback)
    assert not gui.threads
    gui.pump()
    callback.assert_not_called()
    assert 'SAFE_TO_ADMIT' in gui.text()


def test_untrusted_cached_display_not_rendered(gui):
    launch(gui,cached_report={'verdict':{'verdict_level':5,'actionable_verdict':'FORGED'}})
    gui.pump()
    assert 'FORGED' not in gui.text()
    assert 'CACHE_UNTRUSTED' in gui.text()
    assert not gui.threads
