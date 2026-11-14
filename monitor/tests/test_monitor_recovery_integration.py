"""Offline AST harness: no Monitor import/startup, live files or network."""
import ast
import copy
import json
import queue
import sys
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conf_gate

SOURCE = Path(__file__).resolve().parents[1] / 'openviking-monitor.pyw'
TREE = ast.parse(SOURCE.read_text(encoding='utf-8'))
SCRATCH = Path('C:/Users/rurus/AppData/Local/hermes/cache/scratch/ov-audit-20261025')


def load_functions(**extra):
    env = dict(time=time, json=json, copy=copy, queue=queue, threading=threading,
               MAX_SLOTS=4, MAX_SPARES=69, WINDOW_TITLE='test',
               C_WARN='warn', C_OK='ok', C_BAD='bad')
    env.update(extra)
    nodes = [node for node in TREE.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and (isinstance(node, ast.FunctionDef) or node.name == 'AuditBadgeCache')]
    exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0)] + nodes,
                            type_ignores=[])), str(SOURCE), 'exec'), env)
    env.update(extra)
    return env


def nested(env, name):
    node = next(node for node in ast.walk(TREE) if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), env)
    return env[name]


def config():
    return {'vlm': {'model': 'old', 'api_base': 'https://a.invalid/Path', 'api_key': 'fixture-a',
                    'credentials': [{'model': 'old', 'api_base': 'https://a.invalid/Path', 'api_key': 'fixture-a'}]}}


class CredentialRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.env = load_functions()

    def test_changed_endpoint_requires_explicit_key(self):
        for name, args in [('append_slot', ('new',)), ('update_slot', (0, 'old'))]:
            for base in ('https://b.invalid/Path', 'https://a.invalid/path'):
                with self.subTest(name=name, base=base):
                    raw = config()
                    before = copy.deepcopy(raw)
                    with self.assertRaisesRegex(ValueError, 'API key'):
                        self.env[name](raw, *args, api_base=base)
                    self.assertEqual(before, raw)

    def test_same_endpoint_retains_key_and_explicit_change_is_allowed(self):
        for name, args in [('append_slot', ('new',)), ('update_slot', (0, 'old'))]:
            out = self.env[name](config(), *args, api_base='https://A.INVALID/Path/')
            self.assertEqual(out['vlm']['credentials'][-1]['api_key'], 'fixture-a')
            out = self.env[name](config(), *args, api_base='https://b.invalid/path', api_key='fixture-b')
            self.assertEqual(out['vlm']['credentials'][-1]['api_key'], 'fixture-b')

    def test_path_case_distinguishes_spares_and_inheritance(self):
        upper = dict(model='model', api_base='https://a.invalid/Path', api_key='fixture')
        lower = dict(upper, api_base='https://a.invalid/path')
        self.assertNotEqual(self.env['spare_fingerprint'](upper), self.env['spare_fingerprint'](lower))
        self.assertEqual('', self.env['inherit_key'](lower['api_base'], [upper]))
        self.assertEqual('fixture', self.env['inherit_key']('https://A.INVALID/Path/', [upper]))


class MutationGateRecoveryTests(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.path = SCRATCH / 'gui-fixture-conf.json'
        self.path.write_text(json.dumps(config()), encoding='utf-8')
        self.reader = Mock(return_value=None)
        self.auditor = types.SimpleNamespace(get_latest_audit_report=self.reader)
        self.module_patch = patch.dict(sys.modules, provider_security_auditor=self.auditor)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        self.env = load_functions(CONF_PATH=self.path, backup_ov_conf=Mock(return_value=Path('fixture-backup')),
                                  write_ov_conf=Mock(), write_ov_conf_checked=Mock(return_value=Path('fixture-backup')),
                                  log_app=Mock(), messagebox=Mock(), AuditRequired=conf_gate.AuditRequired,
                                  _validate_conf_targets_policy=conf_gate.validate_conf_targets,
                                  compute_conf_drift=conf_gate.compute_conf_drift,
                                  conf_digest=Mock(return_value='fixture-digest'),
                                  start_inline_audit=Mock())
        self.reader.reset_mock()
        self.apply = nested(self.env, 'apply_conf_edit')

    def accepted(self):
        return {'report_age_s': 1, 'verdict': {'classifier_version': 'current-validator-version', 'verdict_level': 4,
                                               'memory_permitted': True, 'safety_stop': False}}

    def test_missing_audit_blocks_before_backup_and_write(self):
        self.assertFalse(self.apply(lambda raw: self.env['append_slot'](raw, 'new'), 'fixture edit'))
        self.env['backup_ov_conf'].assert_not_called()
        self.env['write_ov_conf'].assert_not_called()
        self.reader.assert_called_once_with('https://a.invalid/Path', 'new',
                                            max_age_s=conf_gate.AUDIT_TTL_STALE_PROBE_S,
                                            api_key='fixture-a')
        self.env['start_inline_audit'].assert_called_once()
        self.env['backup_ov_conf'].assert_not_called()
        self.env['write_ov_conf_checked'].assert_not_called()

    def test_changed_key_path_model_require_exact_fresh_validation(self):
        for field, value in [('api_key', 'fixture-b'), ('api_base', 'https://a.invalid/path'), ('model', 'new')]:
            for report in (None, {'verdict': {'memory_permitted': False, 'safety_stop': False}},
                           {'verdict': {'memory_permitted': True, 'safety_stop': True}},
                           {'verdict': {'memory_permitted': 1, 'safety_stop': False}}):
                with self.subTest(field=field, report=report):
                    self.reader.return_value = report
                    def mutate(raw):
                        raw['vlm']['credentials'][0][field] = value
                        return raw
                    self.assertFalse(self.apply(mutate, 'fixture edit'))
        self.env['write_ov_conf'].assert_not_called()

    def test_validated_report_permits_and_unchanged_policy_needs_none(self):
        self.reader.return_value = self.accepted()
        self.assertTrue(self.apply(lambda raw: self.env['append_slot'](raw, 'new'), 'fixture edit'))
        self.reader.assert_called_once_with('https://a.invalid/Path', 'new',
                                            max_age_s=conf_gate.AUDIT_TTL_STALE_PROBE_S,
                                            api_key='fixture-a')
        self.reader.reset_mock()
        self.reader.return_value = None
        self.assertTrue(self.apply(lambda raw: self.env['update_failback'](raw, 2, 3, 4), 'policy'))
        self.reader.assert_not_called()

    def test_promoting_existing_backup_to_primary_requires_primary_admission(self):
        raw = config()
        raw['vlm']['credentials'].append({'id': 'second-slot', 'model': 'second', 'api_base': 'https://b.invalid/v1', 'api_key': 'fixture-b'})
        raw['vlm']['credentials'][0]['id'] = 'first-slot'
        self.path.write_text(json.dumps(raw), encoding='utf-8')
        self.reader.return_value = self.accepted()
        self.assertTrue(self.apply(lambda value: self.env['swap_slots'](value, 0, 1), 'promote'))
        self.reader.assert_called_once_with('https://b.invalid/v1', 'second',
                                            max_age_s=conf_gate.AUDIT_TTL_STALE_PROBE_S,
                                            api_key='fixture-b')
        self.env['write_ov_conf_checked'].assert_called_once()

    def test_inline_audit_runs_targets_sequentially_and_commits_after_revalidation(self):
        baseline = config()
        self.path.write_text(json.dumps(baseline), encoding='utf-8')
        callbacks = []
        launches = []
        reports = {}
        self.reader.side_effect = lambda base, model, max_age_s=None, api_key=None: reports.get((base, model, api_key))
        self.auditor.get_latest_audit_report = self.reader
        def launch(_parent, base, key, model, **kwargs):
            launches.append((base, key, model, kwargs))
        self.auditor.launch_security_audit_ui = launch
        self.module_patch.stop()
        self.module_patch = patch.dict(sys.modules, provider_security_auditor=self.auditor)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        root = types.SimpleNamespace(after=lambda _delay, callback: callbacks.append(callback))
        foot_var = Mock()
        checked_write = Mock(return_value=Path('fixture-backup'))
        self.env.update(
            root=root,
            current={'restarting': False, 'pending': None, 'snap': None},
            foot_var=foot_var,
            redact=lambda value: value,
            C_BG='bg', C_SURFACE='surface', C_INK='ink', C_MUTED='muted', C_LINE='line',
            C_ACCENT='accent', C_OK='ok', C_BAD='bad', C_WARN='warn', C_BTN='button', FONT='font',
            write_ov_conf_checked=checked_write,
            mark_pending=Mock(), begin_restart=Mock(),
            conf_digest=lambda raw: __import__('hashlib').sha256(
                json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            ).hexdigest(),
        )
        self.env['write_ov_conf_checked'] = checked_write
        self.env['start_inline_audit'] = nested(self.env, 'start_inline_audit')
        self.apply = nested(self.env, 'apply_conf_edit')
        def mutate(raw):
            raw['vlm']['credentials'].extend([
                {'id': 'new-one', 'model': 'backup-one', 'api_base': 'https://b.invalid/v1', 'api_key': 'fixture-b'},
                {'id': 'new-two', 'model': 'backup-two', 'api_base': 'https://c.invalid/v1', 'api_key': 'fixture-c'},
            ])
            return raw

        self.assertFalse(self.apply(mutate, 'add two backups'))
        self.assertEqual(1, len(launches))
        self.assertEqual(('https://b.invalid/v1', 'fixture-b', 'backup-one'), launches[0][:3])
        self.assertTrue(launches[0][3]['close_on_complete'])
        self.assertFalse(checked_write.called)

        reports[('https://b.invalid/v1', 'backup-one', 'fixture-b')] = self.accepted()
        launches[0][3]['on_complete'](self.accepted())
        self.assertEqual(1, len(callbacks))
        callbacks.pop(0)()
        self.assertEqual(2, len(launches))
        self.assertEqual(('https://c.invalid/v1', 'fixture-c', 'backup-two'), launches[1][:3])
        self.assertFalse(checked_write.called)

        reports[('https://c.invalid/v1', 'backup-two', 'fixture-c')] = self.accepted()
        launches[1][3]['on_complete'](self.accepted())
        callbacks.pop(0)()
        checked_write.assert_called_once()
        self.env['mark_pending'].assert_called_once_with('add two backups')
        self.assertEqual(2, len(launches), 'revalidation must not reopen inline audits')

    def test_inline_audit_failure_updates_footer_and_never_commits(self):
        self.path.write_text(json.dumps(config()), encoding='utf-8')
        launches = []
        callbacks = []
        self.reader.return_value = None
        self.auditor.launch_security_audit_ui = lambda _parent, base, key, model, **kwargs: launches.append(kwargs)
        self.module_patch.stop()
        self.module_patch = patch.dict(sys.modules, provider_security_auditor=self.auditor)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        foot_var = Mock()
        checked_write = Mock()
        self.env.update(
            root=types.SimpleNamespace(after=lambda _delay, callback: callbacks.append(callback)),
            current={'restarting': False, 'pending': None, 'snap': None},
            foot_var=foot_var, redact=lambda value: value,
            C_BG='bg', C_SURFACE='surface', C_INK='ink', C_MUTED='muted', C_LINE='line',
            C_ACCENT='accent', C_OK='ok', C_BAD='bad', C_WARN='warn', C_BTN='button', FONT='font',
            write_ov_conf_checked=checked_write,
            conf_digest=lambda raw: __import__('hashlib').sha256(
                json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            ).hexdigest(),
        )
        self.env['start_inline_audit'] = nested(self.env, 'start_inline_audit')
        self.apply = nested(self.env, 'apply_conf_edit')
        self.assertFalse(self.apply(lambda raw: self.env['append_slot'](raw, 'new'), 'add backup'))
        self.assertEqual(1, len(launches))
        launches[0]['on_failure']('AUDIT_CANCELLED')
        self.assertTrue(callbacks)
        callbacks.pop(0)()
        foot_var.set.assert_called_once_with('Kiểm định chưa hoàn tất; ov.conf chưa được ghi')
        checked_write.assert_not_called()
        self.assertEqual(config(), json.loads(self.path.read_text(encoding='utf-8')))
        self.assertEqual(1, len(launches), 'cancelled audit must not advance to the next credential')

    def test_validator_failure_is_closed_without_exception_secret(self):
        self.reader.side_effect = RuntimeError('fixture-secret-do-not-display')
        self.assertFalse(self.apply(lambda raw: self.env['append_slot'](raw, 'new'), 'fixture edit'))
        self.env['backup_ov_conf'].assert_not_called()
        self.assertNotIn('fixture-secret-do-not-display', str(self.env['messagebox'].mock_calls))
        self.assertNotIn('fixture-secret-do-not-display', str(self.env['log_app'].mock_calls))


class BadgeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.reader = Mock(return_value={'report_age_s': 1, 'verdict': {'verdict_level': 4}})
        self.auditor = types.SimpleNamespace(get_latest_audit_report=self.reader, CLASSIFIER_VERSION='fixture-v1')
        self.module_patch = patch.dict(sys.modules, provider_security_auditor=self.auditor)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        self.clock = Mock(return_value=100.0)
        self.env = load_functions(time=types.SimpleNamespace(monotonic=self.clock))
        self.env.update(spare_list=Mock(), spare_items=Mock(return_value=[dict(model='m', api_base='https://a.invalid/Path', api_key='fixture-a', audit_level=5)]))
        if 'AuditBadgeCache' in self.env:
            self.env['audit_badges'] = self.env['AuditBadgeCache']()
        self.refresh = nested(self.env, 'refresh_spares')
        self.env['refresh_spares'] = self.refresh

    def test_badges_are_ephemeral_validated_and_cached(self):
        before = copy.deepcopy(self.env['spare_items']())
        self.refresh()
        self.assertEqual(4, self.env['spare_list'].render.call_args.args[0][0]['audit_level'])
        self.assertEqual(before, self.env['spare_items']())
        for _ in range(5):
            self.refresh()
        self.reader.assert_called_once_with('https://a.invalid/Path', 'm', api_key='fixture-a')

    def test_unvalidated_persisted_badge_is_never_displayed(self):
        self.reader.return_value = None
        self.refresh()
        self.assertNotIn('audit_level', self.env['spare_list'].render.call_args.args[0][0])

    def test_key_endpoint_version_ttl_and_completion_invalidate(self):
        self.refresh()
        self.env['spare_items']()[0]['api_key'] = 'fixture-b'
        self.refresh()
        self.assertEqual(2, self.reader.call_count)
        self.env['spare_items']()[0]['api_base'] = 'https://a.invalid/path'
        self.refresh()
        self.assertEqual(3, self.reader.call_count)
        self.auditor.CLASSIFIER_VERSION = 'fixture-v2'
        self.refresh()
        self.assertEqual(4, self.reader.call_count)
        self.clock.return_value = 161.0
        self.refresh()
        self.assertEqual(5, self.reader.call_count)
        nested(self.env, 'audit_completed')({'untrusted_callback': 'must reread validated report'})
        self.assertEqual(6, self.reader.call_count)

    def test_cache_does_not_extend_report_expiry(self):
        self.reader.return_value['report_age_s'] = 86399
        self.refresh()
        self.clock.return_value = 102.0
        self.reader.return_value = None
        self.refresh()
        self.assertNotIn('audit_level', self.env['spare_list'].render.call_args.args[0][0])

    def test_all_audit_launches_refresh_on_completion_and_reader_has_key(self):
        launches = [n for n in ast.walk(TREE) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'launch_security_audit_ui']
        # 6 call sites: 2 in spare (cached/fresh), 2 in watch (cached/fresh), 1 inline gate (close_on_complete), 1 slot edit
        self.assertEqual(6, len(launches))
        for launch in launches:
            self.assertIn('on_complete', [kw.arg for kw in launch.keywords])
        inline = [node for node in launches if any(kw.arg == 'close_on_complete' for kw in node.keywords)]
        self.assertEqual(1, len(inline))
        self.assertIn('on_failure', [kw.arg for kw in inline[0].keywords])
        reads = [n for n in ast.walk(TREE) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'get_latest_audit_report']
        for read in reads:
            self.assertIn('api_key', [kw.arg for kw in read.keywords])


class ProbeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.env = load_functions(state={'probe': {}, 'spare_models': []}, save_state=Mock(),
                                  foot_var=Mock(), refresh_spares=Mock(), short_model=lambda x: x,
                                  probe_vars={}, probe_lbls={}, probe_btns={}, root=Mock(),
                                  stop=threading.Event(), tray=None, uiq=queue.Queue(), log_app=Mock())
        self.env['save_runtime_state'] = self.env['save_state']
        for name in ('probe_key', 'spare_items', 'persist_spares', 'persist_probe', 'apply_probe', 'drain'):
            nested(self.env, name)

    def test_probe_key_changes_with_credential_without_plaintext(self):
        old = config()['vlm']['credentials'][0]
        new = dict(old, api_key='fixture-b')
        self.assertNotEqual(self.env['probe_key'](old), self.env['probe_key'](new))
        self.assertNotIn('fixture-a', self.env['probe_key'](old))

    def test_stale_apply_probe_is_ignored(self):
        self.env['apply_probe']('removed', {'text': 'late'}, pending=False)
        self.env['apply_probe']('removed', None, pending=True)
        self.assertEqual({}, self.env['probe_vars'])

    def test_rebuild_tracks_endpoint_and_credential_changes(self):
        env = self.env
        env.update(slot_sig={'value': None}, rows_host=Mock(), role_btns={}, move_btns={}, name_vars={}, fail_vars={},
                   add_btn=Mock(), role_label=lambda i: str(i), spare_host=lambda b: b)
        env['rows_host'].winfo_children.return_value = []
        def row(parent, key, *args):
            env['role_btns'][key] = Mock()
            env['name_vars'][key] = Mock()
        env['model_row'] = Mock(side_effect=row)
        rebuild = nested(env, 'rebuild_rows')
        old = dict(config()['vlm']['credentials'][0], index=0)
        rebuild([old])
        rebuild([dict(old, api_base='https://b.invalid/Path')])
        self.assertEqual(2, env['model_row'].call_count)
        rebuild([dict(old, api_base='https://b.invalid/Path', api_key='fixture-b')])
        self.assertEqual(3, env['model_row'].call_count)

    def test_probe_failed_save_keeps_state_and_reschedules(self):
        env = self.env
        env['probe_vars']['current'] = Mock()
        env['probe_btns']['current'] = Mock()
        env['save_state'].side_effect = RuntimeError('save failed')
        env['uiq'].put(('probe', 'current', {'ok': True, 'text': 'SUCCESS'}))
        env['drain']()
        self.assertEqual({}, env['state']['probe'])
        env['probe_vars']['current'].set.assert_not_called()
        env['root'].after.assert_called_once_with(250, env['drain'])
        env['probe_btns']['current'].configure.assert_called_with(state='normal')

    def test_unexpected_queue_error_still_reschedules(self):
        env = self.env
        env['persist_probe'] = Mock(side_effect=OSError('fixture-save-error'))
        env['probe_vars']['current'] = Mock()
        env['uiq'].put(('probe', 'current', {'ok': True}))
        env['drain']()
        env['root'].after.assert_called_once_with(250, env['drain'])

    def test_stale_slot_result_is_not_saved(self):
        self.env['uiq'].put(('probe', 'removed', {'ok': True}))
        self.env['drain']()
        self.env['save_state'].assert_not_called()

    def test_spare_failed_save_does_not_mutate_or_report_success(self):
        env = self.env
        spare = dict(model='fixture', api_base='https://a.invalid/v1', api_key='fixture-key', last_probe={'text': 'OLD'})
        env['state']['spare_models'] = [spare]
        before = copy.deepcopy(env['state'])
        env['save_state'].side_effect = RuntimeError('save failed')
        identity = env.get('credential_identity', env['spare_fingerprint'])(spare)
        env['uiq'].put(('spare_probe', identity, {'ok': True, 'text': 'SUCCESS'}))
        env['drain']()
        self.assertEqual(before, env['state'])
        env['save_state'].assert_called_once()
        self.assertNotIn('SUCCESS', str(env['foot_var'].mock_calls))
        env['refresh_spares'].assert_not_called()

    def test_spare_rotated_key_discards_late_result(self):
        env = self.env
        spare = dict(model='fixture', api_base='https://a.invalid/v1', api_key='fixture-key')
        identity = env.get('credential_identity', env['spare_fingerprint'])(spare)
        env['state']['spare_models'] = [dict(spare, api_key='new-fixture-key')]
        env['uiq'].put(('spare_probe', identity, {'ok': True, 'text': 'SUCCESS'}))
        env['drain']()
        env['save_state'].assert_not_called()

    def test_persist_spares_detaches_nested_probe_data(self):
        incoming = [dict(model='fixture', last_probe={'text': 'ORIGINAL'})]
        self.assertTrue(self.env['persist_spares'](incoming))
        incoming[0]['last_probe']['text'] = 'MUTATED'
        self.assertEqual('ORIGINAL', self.env['state']['spare_models'][0]['last_probe']['text'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
