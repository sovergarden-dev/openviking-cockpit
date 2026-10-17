import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
"""Adversarial reference tests; not the unavailable 26 legacy suites."""
import concurrent.futures
import itertools
import json
import math
import unittest
from dataclasses import replace
from unittest.mock import patch

import reference_core_v31 as c


def good(**changes):
    base = c.Evidence(coverage=c.Tier0Coverage(frozenset(c.Tier0Requirement)),
                      role=c.Assessment.PASS, schema=c.Assessment.PASS,
                      capability=c.Assessment.PASS, logic=c.Assessment.PASS,
                      json_class=c.JsonClass.STRICT, latency_s=1.0,
                      required_evidence_complete=True)
    return replace(base, **changes)


class LatchTests(unittest.TestCase):
    def test_initial_is_not_coverage(self):
        latch = c.SecurityLatch()
        self.assertIs(latch.state, c.SecurityState.NO_VIOLATION_OBSERVED)
        self.assertFalse(latch.safety_stop)
        self.assertEqual(c.finalize(c.Evidence(), latch_state=latch.state).level, 2)

    def test_suspect_sticky(self):
        latch = c.SecurityLatch()
        latch.observe(c.SecurityState.SUSPECT)
        self.assertIs(latch.observe(c.SecurityState.NO_VIOLATION_OBSERVED), c.SecurityState.SUSPECT)

    def test_violation_sticky(self):
        latch = c.SecurityLatch()
        latch.observe(c.SecurityState.VIOLATED)
        latch.observe(c.SecurityState.SUSPECT)
        self.assertIs(latch.observe(c.SecurityState.NO_VIOLATION_OBSERVED), c.SecurityState.VIOLATED)
        self.assertTrue(latch.safety_stop)

    def test_new_run_is_independent(self):
        first, second = c.SecurityLatch(), c.SecurityLatch()
        first.record_finding(confirmed=True)
        self.assertFalse(second.safety_stop)

    def test_opt_in_confirmed_stops_legacy(self):
        latch = c.SecurityLatch()
        latch.record_finding(confirmed=True, opt_in=True)
        self.assertEqual(c.finalize(good(), latch_state=latch.state).level, 1)
        record = c.legacy_record(good(), latch_state=latch.state)
        self.assertEqual(set(record), c.LEGACY_KEYS)
        self.assertEqual(record["actionable_verdict"], "STOP")

    def test_opt_in_unconfirmed_suspect(self):
        latch = c.SecurityLatch()
        latch.record_finding(confirmed=False, opt_in=True)
        self.assertFalse(latch.safety_stop)
        self.assertEqual(c.finalize(good(), latch_state=latch.state).level, 2)

    def test_parallel_join(self):
        latch = c.SecurityLatch()
        events = [c.SecurityState.NO_VIOLATION_OBSERVED, c.SecurityState.SUSPECT,
                  c.SecurityState.VIOLATED] * 400
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(latch.observe, events))
        self.assertIs(latch.state, c.SecurityState.VIOLATED)

    def test_latch_rejects_coercion(self):
        for value in (True, 1, "VIOLATED", None):
            with self.subTest(value=value), self.assertRaises(TypeError):
                c.SecurityLatch().observe(value)
        for kwargs in ({"confirmed": 1}, {"confirmed": True, "opt_in": "yes"}):
            with self.assertRaises(TypeError):
                c.SecurityLatch().record_finding(**kwargs)


class DecisionTests(unittest.TestCase):
    def test_fast_boundaries(self):
        for t in (0, 0.001, 3):
            self.assertEqual(c.finalize(good(latency_s=t)).level, 5)

    def test_slow_boundaries(self):
        for t in (3.000001, 9.999, 10):
            self.assertEqual(c.finalize(good(latency_s=t)).level, 4)

    def test_over_ten(self):
        self.assertEqual(c.finalize(good(latency_s=10.000001, pass_slow=True)).level, 3)

    def test_pass_slow_ceiling(self):
        self.assertEqual(c.finalize(good(pass_slow=True)).level, 4)

    def test_quality_failures(self):
        for field in ("role", "schema", "capability", "logic"):
            with self.subTest(field=field):
                self.assertEqual(c.finalize(good(**{field: c.Assessment.FAIL})).level, 3)

    def test_missing_assessments(self):
        for field in ("role", "schema", "capability", "logic"):
            with self.subTest(field=field):
                self.assertEqual(c.finalize(good(**{field: c.Assessment.MISSING})).level, 2)

    def test_nonstrict_and_invalid(self):
        for kind in (c.JsonClass.NONSTRICT, c.JsonClass.INVALID):
            d = c.finalize(good(json_class=kind))
            self.assertEqual(d.level, 3)
            self.assertFalse(d.memory_allowed)

    def test_missing_json(self):
        self.assertEqual(c.finalize(good(json_class=c.JsonClass.MISSING)).level, 2)

    def test_missing_latency(self):
        self.assertEqual(c.finalize(good(latency_s=None)).level, 2)

    def test_missing_required(self):
        self.assertEqual(c.finalize(good(required_evidence_complete=False)).level, 2)

    def test_every_coverage_subset(self):
        checks = list(c.Tier0Requirement)
        for bits in itertools.product((False, True), repeat=4):
            coverage = c.Tier0Coverage(frozenset(x for x, b in zip(checks, bits) if b))
            self.assertEqual(c.finalize(good(coverage=coverage)).level, 5 if all(bits) else 2)

    def test_security_priority_over_missing_and_fail(self):
        for state, expected in ((c.SecurityState.SUSPECT, 2), (c.SecurityState.VIOLATED, 1)):
            self.assertEqual(c.finalize(c.Evidence(security=state)).level, expected)
            self.assertEqual(c.finalize(good(schema=c.Assessment.FAIL), latch_state=state).level, expected)

    def test_evidence_violation_cannot_be_cleared_by_snapshot(self):
        self.assertEqual(c.finalize(good(security=c.SecurityState.VIOLATED)).level, 1)

    def test_missing_role_precedes_known_fail(self):
        self.assertEqual(c.finalize(good(role=c.Assessment.MISSING, logic=c.Assessment.FAIL)).level, 2)

    def test_enum_validation(self):
        for field, value in (("security", 0), ("json_class", "STRICT"), ("role", "PASS"),
                             ("schema", True), ("capability", None), ("logic", 1)):
            with self.subTest(field=field), self.assertRaises(TypeError):
                good(**{field: value})

    def test_finite_latency_validation(self):
        for value in (True, False, "1", math.nan, math.inf, -math.inf, -1, 10**1000):
            with self.subTest(value=repr(value)), self.assertRaises((TypeError, ValueError)):
                good(latency_s=value)

    def test_boolean_validation(self):
        for field in ("pass_slow", "required_evidence_complete"):
            with self.assertRaises(TypeError):
                good(**{field: 1})

    def test_coverage_validation(self):
        for value in (set(), [c.Tier0Requirement.TRANSPORT_ROUTING], frozenset({"transport"})):
            with self.assertRaises(TypeError):
                c.Tier0Coverage(value)

    def test_decision_rejects_forged_flags(self):
        for args in ((3, c.DecisionReason.FAILED_QUALITY, True, False),
                     (1, c.DecisionReason.CONFIRMED_VIOLATION, False, False),
                     (True, c.DecisionReason.VERIFIED_FAST, True, False),
                     (5, "VERIFIED_FAST", True, False)):
            with self.assertRaises((TypeError, ValueError)):
                c.Decision(*args)

    def test_finalizer_argument_validation(self):
        with self.assertRaises(TypeError):
            c.finalize({})
        with self.assertRaises(TypeError):
            c.finalize(good(), latch_state=2)

    def test_exhaustive_table(self):
        # 46,656 deterministic rows, independent explicit oracle.
        rows = 0
        for state, covered, assessments, kind, latency, slow, complete in itertools.product(
                list(c.SecurityState), (False, True),
                list(itertools.product(list(c.Assessment), repeat=4)),
                list(c.JsonClass), (None, 0, 3, 3.001, 10, 10.001), (False, True), (False, True)):
            e = good(security=state,
                     coverage=c.Tier0Coverage(frozenset(c.Tier0Requirement) if covered else frozenset()),
                     role=assessments[0], schema=assessments[1], capability=assessments[2],
                     logic=assessments[3], json_class=kind, latency_s=latency,
                     pass_slow=slow, required_evidence_complete=complete)
            if state == c.SecurityState.VIOLATED:
                expected = 1
            elif state == c.SecurityState.SUSPECT:
                expected = 2
            elif (not covered or not complete or latency is None or kind == c.JsonClass.MISSING
                  or c.Assessment.MISSING in (assessments[0], assessments[2], assessments[3])
                  or (kind == c.JsonClass.STRICT and assessments[1] == c.Assessment.MISSING)):
                expected = 2
            elif (kind != c.JsonClass.STRICT or c.Assessment.FAIL in assessments or latency > 10):
                expected = 3
            elif latency > 3 or slow:
                expected = 4
            else:
                expected = 5
            actual = c.finalize(e)
            self.assertEqual(actual.level, expected)
            self.assertEqual(actual.memory_allowed, expected in (4, 5))
            self.assertEqual(actual.safety_stop, expected == 1)
            rows += 1
        self.assertEqual(rows, 46656)

    def test_baseline_tier0_ids_exact(self):
        self.assertEqual({x.value for x in c.Tier0Requirement}, {
            'transport_routing', 'ansi_control_hygiene', 'tool_call_hijack', 'canary_isolation'})

    def test_ansi_coverage_is_required(self):
        coverage = c.Tier0Coverage(frozenset(c.Tier0Requirement) - {
            c.Tier0Requirement.ANSI_CONTROL_HYGIENE})
        self.assertEqual(c.finalize(good(coverage=coverage)).level, 2)

    def test_invalid_nonstrict_schema_missing_regression(self):
        for kind, role in itertools.product((c.JsonClass.INVALID, c.JsonClass.NONSTRICT),
                                            (c.Assessment.PASS, c.Assessment.FAIL)):
            with self.subTest(kind=kind, role=role):
                decision = c.finalize(good(json_class=kind, role=role, schema=c.Assessment.MISSING))
                self.assertEqual(decision.level, 3)
                self.assertFalse(decision.memory_allowed)

    def test_strict_still_requires_schema_even_role_fail(self):
        for role in (c.Assessment.PASS, c.Assessment.FAIL):
            self.assertEqual(c.finalize(good(role=role, schema=c.Assessment.MISSING)).level, 2)

    def test_invalid_still_requires_core_evidence(self):
        for kind in (c.JsonClass.INVALID, c.JsonClass.NONSTRICT):
            for field in ('role', 'capability', 'logic'):
                with self.subTest(kind=kind, field=field):
                    self.assertEqual(c.finalize(good(json_class=kind, schema=c.Assessment.MISSING,
                                                    **{field: c.Assessment.MISSING})).level, 2)
            for changes in (dict(latency_s=None), dict(required_evidence_complete=False),
                            dict(coverage=c.Tier0Coverage())):
                self.assertEqual(c.finalize(good(json_class=kind, schema=c.Assessment.MISSING,
                                                **changes)).level, 2)

    def test_conditional_schema_keeps_security_priority(self):
        for kind in (c.JsonClass.INVALID, c.JsonClass.NONSTRICT):
            e = good(json_class=kind, schema=c.Assessment.MISSING)
            self.assertEqual(c.finalize(e, latch_state=c.SecurityState.VIOLATED).level, 1)
            self.assertEqual(c.finalize(e, latch_state=c.SecurityState.SUSPECT).level, 2)

    def test_legacy_exact_names(self):
        for e in (good(), c.Evidence(), good(schema=c.Assessment.FAIL)):
            record = c.legacy_record(e)
            self.assertEqual(set(record), c.LEGACY_KEYS)
            self.assertEqual(record["classifier_version"], c.REFERENCE_VERSION)


class JSONTests(unittest.TestCase):
    def assert_bad(self, raw, **kwargs):
        with self.assertRaises(c.StrictJSONError):
            c.strict_json_loads(raw, **kwargs)

    def test_rfc_whitespace(self):
        self.assertEqual(c.strict_json_loads(' \t\r\n{"a":1}\n '), {"a": 1})

    def test_no_broad_strip(self):
        for whitespace in ("\xa0", "\u2003", "\u2028", "\ufeff", "\v", "\f"):
            with self.subTest(whitespace=repr(whitespace)):
                self.assert_bad(whitespace + '{"a":1}' + whitespace)

    def test_duplicate_identical(self):
        self.assert_bad('{"a":1,"a":1}')

    def test_duplicate_bool_number(self):
        self.assert_bad('{"a":true,"a":1}')

    def test_duplicate_decoded_keys(self):
        self.assert_bad('{"a":1,"\\u0061":2}')

    def test_nested_duplicate(self):
        self.assert_bad('{"x":{"k":1,"k":2}}')

    def test_multiple_values(self):
        for raw in ('{}{}', '{"a":true}{"a":1}', '1 2', 'null []'):
            self.assert_bad(raw)

    def test_no_salvage(self):
        for raw in ('prefix {"a":1}{"a":2}', '```json\n{}\n```', '{} trailing', '//x\n{}', '{"a":1,}'):
            self.assert_bad(raw)

    def test_constants(self):
        for raw in ('NaN', 'Infinity', '-Infinity', '{"a":NaN}'):
            self.assert_bad(raw)

    def test_overflow(self):
        for raw in ('1e400', '-1e999', '{"x":1e400}'):
            self.assert_bad(raw)

    def test_utf8_and_bom(self):
        self.assert_bad(b'"\xff"')
        self.assert_bad(b'\xef\xbb\xbf{}')
        self.assertEqual(c.strict_json_loads('"Việt"'.encode()), 'Việt')

    def test_surrogates(self):
        for raw in ('"\\ud800"', '"\\udfff"', '{"\\ud800":1}', '"\ud800"'):
            self.assert_bad(raw)
        self.assertEqual(c.strict_json_loads('"\\ud83d\\ude00"'), '😀')

    def test_byte_cap_before_parser(self):
        with patch.object(c.json, 'loads', side_effect=AssertionError('must not parse')):
            self.assert_bad('"éé"', limits=c.JSONLimits(max_bytes=5))
            self.assert_bad(b' ' * 7, limits=c.JSONLimits(max_bytes=6))

    def test_depth_cap_before_parser(self):
        with patch.object(c.json, 'loads', side_effect=AssertionError('must not parse')):
            self.assert_bad('[' * 33 + '0' + ']' * 33)
            self.assert_bad('[' * 2000 + '0' + ']' * 2000)

    def test_node_cap_before_parser(self):
        with patch.object(c.json, 'loads', side_effect=AssertionError('must not parse')):
            self.assert_bad('[1,2,3]', limits=c.JSONLimits(max_nodes=3))
            self.assert_bad('{"a":1}', limits=c.JSONLimits(max_nodes=2))

    def test_exact_budget_boundaries(self):
        self.assertEqual(c.strict_json_loads('[1,2]', c.JSONLimits(max_bytes=5, max_depth=1, max_nodes=3)), [1, 2])
        self.assertEqual(c.strict_json_loads('{"a":1}', c.JSONLimits(max_nodes=3)), {"a": 1})

    def test_quote_aware_depth(self):
        value = {'s': '[' * 100 + '\\"}' * 100}
        raw = json.dumps(value)
        self.assertEqual(c.strict_json_loads(raw, c.JSONLimits(max_depth=1)), value)

    def test_malformed_structures(self):
        for raw in ('', '[', ']', '[}', '{]', '"x\\', '[1,,2]', '{"a" 1}', '01', '+1', '[true false]'):
            self.assert_bad(raw)

    def test_valid_scalar_types(self):
        for raw, expected in (('true', True), ('false', False), ('null', None), ('1', 1), ('1.5', 1.5), ('"x"', 'x')):
            value = c.strict_json_loads(raw)
            self.assertIs(type(value), type(expected))
            self.assertEqual(value, expected)

    def test_limits_and_types(self):
        for kwargs in ({"max_nodes": True}, {"max_depth": 129}, {"max_bytes": 0}, {"max_depth": 1.5}):
            with self.assertRaises(ValueError):
                c.JSONLimits(**kwargs)
        with self.assertRaises(TypeError):
            c.strict_json_loads(bytearray(b'{}'))
        with self.assertRaises(TypeError):
            c.strict_json_loads('{}', limits={})

    def test_evidence_only_classifier(self):
        self.assertIs(c.classify_json('{}').classification, c.JsonClass.STRICT)
        self.assertIs(c.classify_json('prefix {}').classification, c.JsonClass.INVALID)
        outcome = c.classify_json('prefix {}', known_nonstrict=True)
        self.assertIs(outcome.classification, c.JsonClass.NONSTRICT)
        self.assertFalse(hasattr(outcome, 'value'))
        self.assertFalse(c.finalize(good(json_class=outcome.classification)).memory_allowed)

    def test_classifier_invalid_arguments(self):
        with self.assertRaises(TypeError):
            c.classify_json('{}', known_nonstrict=1)
        with self.assertRaises(TypeError):
            c.classify_json(None)

    def test_fixture_separate_from_parser(self):
        self.assertEqual(c.strict_json_loads('{"echo":"n"}'), {"echo": "n"})
        self.assertFalse(c.validate_fixture_schema({"echo": "n"}))

    def test_fixture_bool_is_not_number(self):
        for score in (True, False, math.inf, math.nan, "1", None, 10**1000):
            self.assertFalse(c.validate_fixture_schema({"ok": True, "score": score}))

    def test_fixture_exact_types_and_fields(self):
        self.assertTrue(c.validate_fixture_schema({"ok": False, "score": -1.5}))
        for value in ([], {"ok": 1, "score": 1}, {"ok": True}, {"ok": True, "score": 1, "secret": "x"}):
            self.assertFalse(c.validate_fixture_schema(value))


class CacheTests(unittest.TestCase):
    def identity(self, **changes):
        kwargs = dict(endpoint='https://example.com/API', model='model', api_key='secret', hmac_key=b'x' * 32,
                      probe_version='probe-v1', policy_version='policy-v1',
                      schema_version='schema-v1', config_digest='a' * 64)
        kwargs.update(changes)
        return c.cache_identity(**kwargs)

    def record(self, **changes):
        record = dict(c.legacy_record(good()), epoch_ts=100.0)
        record.update(changes)
        return record

    def test_authority_normalization(self):
        self.assertEqual(self.identity(endpoint='HTTPS://EXAMPLE.COM.:443/API'), self.identity())
        self.assertEqual(c.normalize_endpoint('https://[2001:0db8::1]:443/X'), 'https://[2001:db8::1]/X')

    def test_idna(self):
        self.assertEqual(c.normalize_endpoint('https://tést.example/X'), 'https://xn--tst-bma.example/X')

    def test_path_case_preserved(self):
        self.assertNotEqual(self.identity(endpoint='https://example.com/api'), self.identity())
        self.assertNotEqual(self.identity(endpoint='https://example.com/A%2FB'), self.identity(endpoint='https://example.com/A%2fB'))

    def test_query_case_preserved(self):
        self.assertNotEqual(self.identity(endpoint='https://example.com/API?q=X'), self.identity(endpoint='https://example.com/API?q=x'))

    def test_nondefault_port(self):
        self.assertNotEqual(self.identity(endpoint='https://example.com:444/API'), self.identity())

    def test_no_delimiter_collision(self):
        self.assertNotEqual(self.identity(model='a|b', api_key='c'), self.identity(model='a', api_key='b|c'))
        self.assertNotEqual(self.identity(model='a"], ["b', api_key='c'), self.identity(model='a', api_key='b"], ["c'))

    def test_identity_binds_all_inputs(self):
        baseline = self.identity()
        for change in (dict(model='Model'), dict(model=' model'), dict(api_key='other'),
                       dict(classifier_version='other'), dict(hmac_key=b'y' * 32)):
            self.assertNotEqual(self.identity(**change), baseline)
        self.assertRegex(baseline, r'^[0-9a-f]{64}$')

    def test_identity_versions_and_config_each_bound(self):
        baseline = self.identity()
        for field in ('probe_version', 'policy_version', 'schema_version', 'config_digest'):
            with self.subTest(field=field):
                self.assertNotEqual(self.identity(**{field: 'different'}), baseline)

    def test_identity_version_config_types(self):
        for field in ('probe_version', 'policy_version', 'schema_version', 'config_digest'):
            for value in ('', None, True, 1, '\ud800'):
                with self.subTest(field=field, value=repr(value)), self.assertRaises(ValueError):
                    self.identity(**{field: value})

    def test_identity_versions_config_have_no_defaults(self):
        from inspect import signature, Parameter
        sig = signature(c.cache_identity)
        for field in ('probe_version', 'policy_version', 'schema_version', 'config_digest'):
            self.assertIs(sig.parameters[field].default, Parameter.empty)
            self.assertIs(sig.parameters[field].kind, Parameter.KEYWORD_ONLY)

    def test_identity_version_delimiter_collision(self):
        self.assertNotEqual(self.identity(probe_version='a|b', policy_version='c'),
                            self.identity(probe_version='a', policy_version='b|c'))
        self.assertNotEqual(self.identity(schema_version='a|b', config_digest='c'),
                            self.identity(schema_version='a', config_digest='b|c'))

    def test_invalid_authorities(self):
        for endpoint in ('http://example.com/X', 'https://user:password@example.com/X',
                         'https://example.com/X#', 'https://example.com:0/X',
                         'https://example.com:65536/X', 'https://example.com:/X',
                         'https://example.com:abc/X', 'https://bad_host/X',
                         'https://a..b/X', 'https://[fe80::1%25eth0]/X',
                         'https://example.com\\@evil/X', ' https://example.com/X',
                         'https://example.com/\nX', 'https://example.com/\xa0X',
                         'https://example.com/\x85X', 'https:///X'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                self.identity(endpoint=endpoint)

    def test_identity_types(self):
        for changes in (dict(api_key=True), dict(model=''), dict(hmac_key=b'short'),
                        dict(hmac_key='x' * 32), dict(endpoint=1), dict(model='\ud800')):
            with self.assertRaises(ValueError):
                self.identity(**changes)

    def test_projection_copy_and_allowlist(self):
        source = self.record()
        projected = c.project_cache_record(source)
        self.assertEqual(source, projected)
        self.assertIsNot(source, projected)
        projected['epoch_ts'] = 200
        self.assertEqual(source['epoch_ts'], 100)

    def test_unknown_secret_fields_rejected(self):
        for field in ('api_key', 'authorization', 'headers', 'raw_response', 'error', 'nonce', 'observations'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                c.project_cache_record(self.record(**{field: 'secret'}))

    def test_secret_in_known_enum_rejected(self):
        for field in ('classifier_version', 'actionable_verdict', 'os_security_status', 'role_fitness'):
            with self.assertRaises(ValueError):
                c.project_cache_record(self.record(**{field: 'Bearer secret'}))

    def test_projection_missing_fields(self):
        for field in self.record():
            row = self.record()
            del row[field]
            with self.assertRaises(ValueError):
                c.project_cache_record(row)

    def test_projection_type_strict(self):
        for changes in (dict(verdict_level=True), dict(verdict_level=5.0), dict(verdict_level=6),
                        dict(epoch_ts=True), dict(role_fitness=c.Assessment.PASS),
                        dict(epoch_ts=math.inf), dict(epoch_ts=-1)):
            with self.assertRaises((TypeError, ValueError)):
                c.project_cache_record(self.record(**changes))

    def test_projection_consistency(self):
        for changes in (dict(actionable_verdict='STOP'), dict(os_security_status='VIOLATED'),
                        dict(os_security_status='SUSPECT'), dict(role_fitness='MISSING'), dict(role_fitness='FAIL')):
            with self.assertRaises(ValueError):
                c.project_cache_record(self.record(**changes))

    def test_all_reference_levels_project(self):
        for e in (good(security=c.SecurityState.VIOLATED), c.Evidence(),
                  good(logic=c.Assessment.FAIL), good(pass_slow=True), good()):
            self.assertEqual(c.project_cache_record(dict(c.legacy_record(e), epoch_ts=100))['verdict_level'],
                             c.finalize(e).level)

    def test_fresh_half_open(self):
        self.assertTrue(c.is_fresh(epoch_ts=100, now=100, ttl_s=10))
        self.assertTrue(c.is_fresh(epoch_ts=100, now=109.999, ttl_s=10))
        self.assertFalse(c.is_fresh(epoch_ts=100, now=110, ttl_s=10))
        self.assertFalse(c.is_fresh(epoch_ts=100, now=99, ttl_s=10))
        self.assertFalse(c.is_fresh(epoch_ts=100, now=100, ttl_s=0))

    def test_fresh_rejects_bad_values(self):
        for field in ('epoch_ts', 'now', 'ttl_s'):
            for bad in (True, '100', math.nan, math.inf, -math.inf, -1, 10**1000):
                args = dict(epoch_ts=100, now=100, ttl_s=10)
                args[field] = bad
                with self.subTest(field=field, bad=repr(bad)), self.assertRaises((TypeError, ValueError)):
                    c.is_fresh(**args)

    def test_fresh_overflow_subtraction_is_false(self):
        # Finite nonnegative values; no future timestamp gets accepted.
        self.assertFalse(c.is_fresh(epoch_ts=1e308, now=0, ttl_s=1e308))


if __name__ == '__main__':
    unittest.main()
