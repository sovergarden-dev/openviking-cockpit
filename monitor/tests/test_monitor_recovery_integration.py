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
                                  write_ov_conf=Mock(), log_app=Mock(), messagebox=Mock())
        self.apply = nested(self.env, 'apply_conf_edit')

    def accepted(self):
        return {'verdict': {'classifier_version': 'current-validator-version', 'verdict_level': 4,
                            'memory_permitted': True, 'safety_stop': False}}

    def test_missing_audit_blocks_before_backup_and_write(self):
        self.assertFalse(self.apply(lambda raw: self.env['append_slot'](raw, 'new'), 'fixture edit'))
        self.env['backup_ov_conf'].assert_not_called()
        self.env['write_ov_conf'].assert_not_called()
        self.reader.assert_called_once_with('https://a.invalid/Path', 'new', api_key='fixture-a')
        message = self.env['messagebox'].showerror.call_args.args[1]
        self.assertIn('kiểm định', message)
        self.assertNotIn('fixture-a', message)

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
        self.reader.assert_called_once_with('https://a.invalid/Path', 'new', api_key='fixture-a')
        self.reader.reset_mock()
        self.reader.return_value = None
        self.assertTrue(self.apply(lambda raw: self.env['update_failback'](raw, 2, 3, 4), 'policy'))
        self.reader.assert_not_called()

    def test_reorder_effective_credentials_does_not_freeze_existing_slots(self):
        raw = config()
        raw['vlm']['credentials'].append({'model': 'second'})
        self.path.write_text(json.dumps(raw), encoding='utf-8')
        self.assertTrue(self.apply(lambda value: self.env['swap_slots'](value, 0, 1), 'reorder'))
        self.reader.assert_not_called()

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
        self.assertEqual(3, len(launches))
        for launch in launches:
            self.assertIn('on_complete', [kw.arg for kw in launch.keywords])
        reads = [n for n in ast.walk(TREE) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'get_latest_audit_report']
        for read in reads:
            self.assertIn('api_key', [kw.arg for kw in read.keywords])


class ProbeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.env = load_functions(state={'probe': {}, 'spare_models': []}, save_state=Mock(),
                                  foot_var=Mock(), refresh_spares=Mock(), short_model=lambda x: x,
                                  probe_vars={}, probe_lbls={}, probe_btns={}, root=Mock(),
                                  stop=threading.Event(), tray=None, uiq=queue.Queue(), log_app=Mock())
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
