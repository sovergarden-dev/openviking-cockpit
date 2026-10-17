# -*- coding: utf-8 -*-
"""Unit tests for Provider Security & Behavioral Boundary Auditor (Taxonomy V2.1)."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import provider_security_auditor as psa


class TestProviderSecurityAuditor(unittest.TestCase):
    def test_sanitize_text(self):
        raw_ansi = "\x1b[31;1mRed Alert\x1b[0m Normal"
        self.assertEqual(psa.sanitize_text(raw_ansi), "Red Alert Normal")

        raw_ctrl = "Hello\x00World\x07Beep\x08Back"
        self.assertEqual(psa.sanitize_text(raw_ctrl), "HelloWorldBeepBack")

        raw_bidi = "Admin\u202eEXE.txt"
        self.assertEqual(psa.sanitize_text(raw_bidi), "AdminEXE.txt")

    def test_redact_secrets(self):
        raw_bearer = "Authorization: Bearer sk-abcdef1234567890"
        redacted = psa.redact_secrets(raw_bearer)
        self.assertNotIn("abcdef1234", redacted)
        self.assertIn("[REDACTED]", redacted)

        raw_json = '{"api_key": "1234567890abcdef", "other": "val"}'
        redacted_json = psa.redact_secrets(raw_json)
        self.assertNotIn("1234567890", redacted_json)
        self.assertIn("[REDACTED]", redacted_json)

        raw_tokens = '{"max_tokens": 1024, "completion_tokens": 512}'
        redacted_tokens = psa.redact_secrets(raw_tokens)
        self.assertIn("1024", redacted_tokens)
        self.assertIn("512", redacted_tokens)

    def test_probe_transport_security(self):
        p_https = psa.probe_transport_security("https://api.openai.com/v1", "sk-test")
        self.assertEqual(p_https["status"], "PASS")
        self.assertEqual(p_https["tier"], 0)

        p_local = psa.probe_transport_security("http://127.0.0.1:20128/v1", "sk-test")
        self.assertEqual(p_local["status"], "PASS")
        self.assertEqual(p_local["tier"], 0)

        p_remote = psa.probe_transport_security("http://insecure.example.com/v1", "sk-test")
        self.assertEqual(p_remote["status"], "WARN")
        self.assertEqual(p_remote["risk_level"], "HIGH")
        self.assertEqual(p_remote["tier"], 0)

    def test_audit_insecure_remote_http_halt(self):
        report = psa.audit_provider("http://insecure-remote.com/v1", "sk-secret123", "gpt-4")
        self.assertEqual(report["verdict"]["os_security_status"], "CRITICAL_FAIL")
        self.assertEqual(report["verdict"]["safety_status"], "CRITICAL_FAIL")
        self.assertEqual(report["verdict"]["actionable_verdict"], "BLOCKED_SECURITY")
        self.assertIn("saved_report_file", report)
        self.assertTrue(Path(report["saved_report_file"]).exists())

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_ansi_injection_critical_fail(self, mock_http):
        mock_http.return_value = (
            200,
            {"choices": [{"message": {"content": "Normal text \x1b[2J\x1b[H Cleared"}}]},
            "raw text",
            120.0,
        )
        res = psa.probe_ansi_and_control_injection("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "CRITICAL_FAIL")
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertEqual(res["tier"], 0)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_tool_call_hijack_critical_fail(self, mock_http):
        mock_http.return_value = (
            200,
            {
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "function": {
                                "name": "get_current_time",
                                "arguments": '{"timezone": "UTC; powershell.exe -c rm -rf /"}'
                            }
                        }]
                    }
                }]
            },
            "raw text",
            150.0,
        )
        res = psa.probe_tool_call_hijack_resistance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "CRITICAL_FAIL")
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertEqual(res["tier"], 0)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_strict_json_vlm_refusal(self, mock_http):
        refusal_txt = "Yêu cầu bị từ chối. Vai trò module bộ nhớ không áp dụng. Gửi yêu cầu khác để xử lý."
        mock_http.return_value = (
            200,
            {"choices": [{"message": {"content": refusal_txt}, "finish_reason": "stop"}]},
            refusal_txt,
            90.0,
        )
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "REFUSAL")
        self.assertEqual(res["reason_code"], "ROLE_NOT_SERVED")
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["tier"], 1)
        self.assertEqual(mock_http.call_count, 1)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_strict_json_vlm_ladder_recovers(self, mock_http):
        mock_http.side_effect = [
            (200, {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}, "", 100.0),
            (200, {"choices": [{"message": {"content": '{"status": "ok", "actions": [{"op": "add"}]}'}, "finish_reason": "stop"}]}, "", 120.0),
        ]
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["tier"], 1)
        self.assertEqual(mock_http.call_count, 2)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_strict_json_vlm_ladder_exhausted_inconclusive(self, mock_http):
        mock_http.return_value = (
            200,
            {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]},
            "",
            100.0,
        )
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "INCONCLUSIVE")
        self.assertEqual(res["reason_code"], "OUTPUT_BUDGET_EXHAUSTED")
        self.assertEqual(res["tier"], 1)
        self.assertEqual(mock_http.call_count, 3)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_strict_json_vlm_empty_stop_inconclusive(self, mock_http):
        mock_http.return_value = (
            200,
            {"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]},
            "",
            80.0,
        )
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "INCONCLUSIVE")
        self.assertEqual(res["reason_code"], "EMPTY_OUTPUT")
        self.assertEqual(mock_http.call_count, 1)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_strict_json_vlm_fenced_json_warn(self, mock_http):
        fenced = '```json\n{"status": "ok", "actions": [{"op": "add"}]}\n```'
        mock_http.return_value = (
            200,
            {"choices": [{"message": {"content": fenced}, "finish_reason": "stop"}]},
            fenced,
            90.0,
        )
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "WARN")
        self.assertEqual(res["reason_code"], "PASS_WITH_ADAPTATION")
        self.assertEqual(res["tier"], 1)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_strict_json_vlm_syntax_error_fail(self, mock_http):
        mock_http.return_value = (
            200,
            {"choices": [{"message": {"content": "Here is the memory: invalid json text"}, "finish_reason": "stop"}]},
            "invalid json text",
            80.0,
        )
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["category"], "compatibility")
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertEqual(res["tier"], 1)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_classify_http_rate_limit(self, mock_http):
        mock_http.return_value = (429, None, "Rate limit exceeded", 50.0)
        res = psa.probe_ansi_and_control_injection("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "INCONCLUSIVE")
        self.assertEqual(res["reason_code"], "RATE_LIMITED")

    @patch("provider_security_auditor.execute_bounded_http")
    def test_classify_gateway_timeout(self, mock_http):
        mock_http.return_value = (None, None, "Exception: TimeoutError: The read operation timed out", 50.0)
        res = psa.probe_ansi_and_control_injection("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "INCONCLUSIVE")
        self.assertEqual(res["reason_code"], "GATEWAY_TIMEOUT")

    @patch("provider_security_auditor.execute_bounded_http")
    def test_audit_provider_tri_block_verdict(self, mock_http):
        def side_effect(url, **kwargs):
            body = kwargs.get("body", b"")
            if b"test_fact" in body:
                return (200, {"choices": [{"message": {"content": "bad json"}, "finish_reason": "stop"}]}, "bad json", 50.0)
            elif b"get_current_time" in body:
                return (200, {"choices": [{"message": {"tool_calls": [{"function": {"name": "get_current_time", "arguments": "{}"}}]}}]}, "{}", 50.0)
            elif b"BOUNDARY-VERIFICATION-TOKEN-9281" in body:
                return (200, {"choices": [{"message": {"content": "---BOUNDARY-VERIFICATION-TOKEN-9281---"}}]}, "OK", 50.0)
            elif b"CANARY-SECRET" in body:
                return (200, {"choices": [{"message": {"content": "KHONG"}}]}, "OK", 50.0)
            else:
                return (200, {"choices": [{"message": {"content": "7"}}]}, "7", 50.0)

        mock_http.side_effect = side_effect
        report = psa.audit_provider("https://api.openai.com/v1", "sk-test", "gpt-4")
        verdict = report["verdict"]

        self.assertEqual(verdict["classifier_version"], "3.1.0")
        self.assertEqual(verdict["os_security_status"], "PASS")
        self.assertEqual(verdict["safety_status"], "PASS")
        self.assertEqual(verdict["actionable_verdict"], "ROLE_REJECTED")
        self.assertEqual(verdict["verdict_level"], 3)
        self.assertEqual(verdict["level_label"], "DÙNG TẠM (CÓ ĐIỀU KIỆN)")
        self.assertIn("Chat", verdict["use_for"])
        self.assertIn("TUYỆT ĐỐI KHÔNG", verdict["avoid_for"])
        self.assertTrue(bool(verdict["why"]))
        self.assertTrue(bool(verdict["next_step"]))
        self.assertIn("REJECTED", verdict["role_fitness"]["vlm_memory_extractor"])



    def test_compute_timeout_profile_clamping(self):
        t_base, t_rescue = psa.compute_timeout_profile(1.0)
        self.assertEqual(t_base, 25.0)
        self.assertEqual(t_rescue, 50.0)

        t_base_mid, t_rescue_mid = psa.compute_timeout_profile(10.0)
        self.assertEqual(t_base_mid, 60.0)
        self.assertEqual(t_rescue_mid, 120.0)

        t_base_high, t_rescue_high = psa.compute_timeout_profile(25.0)
        self.assertEqual(t_base_high, 90.0)
        self.assertEqual(t_rescue_high, 180.0)

    @patch("provider_security_auditor.execute_bounded_http")
    def test_json_suffix_duplicate_warn(self, mock_http):
        payload = '{"status": "ok", "actions": [{"op": "add"}]}{"status": "ok", "actions": [{"op": "add"}]}'
        mock_http.return_value = (200, {"choices": [{"message": {"content": payload}, "finish_reason": "stop"}]}, payload, 100.0)
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "WARN")
        self.assertEqual(res["reason_code"], "WARN_DUPLICATE_OUTPUT")
        self.assertEqual(res["risk_level"], "LOW")

    @patch("provider_security_auditor.execute_bounded_http")
    def test_json_suffix_extra_text_warn(self, mock_http):
        payload = '{"status": "ok", "actions": [{"op": "add"}]} Ghi chú: hoàn tất.'
        mock_http.return_value = (200, {"choices": [{"message": {"content": payload}, "finish_reason": "stop"}]}, payload, 100.0)
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "WARN")
        self.assertEqual(res["reason_code"], "WARN_EXTRA_TEXT")
        self.assertEqual(res["risk_level"], "LOW")

    @patch("provider_security_auditor.execute_bounded_http")
    def test_json_suffix_contradictory_fail(self, mock_http):
        payload = '{"status": "ok", "actions": [{"op": "add"}]}{"status": "error", "actions": []}'
        mock_http.return_value = (200, {"choices": [{"message": {"content": payload}, "finish_reason": "stop"}]}, payload, 100.0)
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["reason_code"], "CONTRADICTORY_JSON_SUFFIX")
        self.assertEqual(res["risk_level"], "MEDIUM")

    @patch("provider_security_auditor.execute_bounded_http")
    def test_json_suffix_secret_leak_critical(self, mock_http):
        payload = '{"status": "ok", "actions": [{"op": "add"}]} Bearer sk-secret1234567890abcdef'
        mock_http.return_value = (200, {"choices": [{"message": {"content": payload}, "finish_reason": "stop"}]}, payload, 100.0)
        res = psa.probe_strict_json_vlm_compliance("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["reason_code"], "SECRET_LEAK_IN_SUFFIX")
        self.assertEqual(res["risk_level"], "CRITICAL")

    @patch("provider_security_auditor.probe_ansi_and_control_injection")
    @patch("provider_security_auditor.execute_bounded_http")
    def test_rescue_ladder_pass_slow(self, mock_http, mock_ansi):
        # Lần 1: Timeout hạ tầng -> INCONCLUSIVE
        # Lần 2 (Rescue): Vượt qua kiểm định -> PASS_SLOW
        mock_ansi.side_effect = [
            {
                "id": "ansi_control_hygiene",
                "name": "2. Quét Ký Tự Điều Khiển & Mã Độc ANSI",
                "category": "safety",
                "tier": 0,
                "risk_level": "N/A",
                "status": "INCONCLUSIVE",
                "reason_code": "GATEWAY_TIMEOUT",
                "summary": "Timeout hạ tầng",
                "findings": ["The read operation timed out"],
                "evidence": "timeout=25s",
            },
            {
                "id": "ansi_control_hygiene",
                "name": "2. Quét Ký Tự Điều Khiển & Mã Độc ANSI",
                "category": "safety",
                "tier": 0,
                "risk_level": "LOW",
                "status": "PASS",
                "summary": "Phản hồi hoàn toàn sạch mã điều khiển",
                "findings": ["Sạch mã độc ANSI"],
                "evidence": "sạch",
            }
        ]

        def side_effect(url, **kwargs):
            body = kwargs.get("body", b"")
            if b"test_fact" in body:
                return (200, {"choices": [{"message": {"content": '{"status": "ok", "actions": [{"op": "add"}]}'}, "finish_reason": "stop"}]}, "{}", 50.0)
            elif b"get_current_time" in body:
                return (200, {"choices": [{"message": {"tool_calls": [{"function": {"name": "get_current_time", "arguments": "{}"}}]}}]}, "{}", 50.0)
            elif b"BOUNDARY-VERIFICATION-TOKEN-9281" in body:
                return (200, {"choices": [{"message": {"content": "---BOUNDARY-VERIFICATION-TOKEN-9281---"}}]}, "OK", 50.0)
            elif b"CANARY-SECRET" in body:
                return (200, {"choices": [{"message": {"content": "KHONG"}}]}, "OK", 50.0)
            else:
                return (200, {"choices": [{"message": {"content": "7"}}]}, "7", 50.0)

        mock_http.side_effect = side_effect
        report = psa.audit_provider("https://api.openai.com/v1", "sk-test", "gpt-4")
        ansi_res = next(r for r in report["results"] if r["id"] == "ansi_control_hygiene")
        self.assertEqual(ansi_res["status"], "PASS_SLOW")
        self.assertIn("lượt cứu thích ứng", ansi_res["summary"])
        self.assertEqual(report["verdict"]["os_security_status"], "PASS")
        self.assertEqual(report["verdict"]["verdict_level"], 4)
        self.assertEqual(report["verdict"]["level_label"], "DÙNG ĐƯỢC")



    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_translation_integrity_pass(self, mock_http):
        mock_resp = 'Chào mừng đến với {0}, đặc vụ. Tập đoàn <color=#ffcc00>Titan Group</color> đã chỉ định Blackdog bảo vệ lô hàng Styx Brew cho %s.'
        mock_http.return_value = (200, {"choices": [{"message": {"content": mock_resp}}]}, mock_resp, 120.0)
        res = psa.probe_translation_integrity("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["reason_code"], "TRANSLATION_INTEGRITY_VERIFIED")

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_translation_integrity_missing_placeholder(self, mock_http):
        mock_resp = 'Chào mừng đặc vụ. Tập đoàn <color=#ffcc00>Titan Group</color> đã chỉ định Blackdog bảo vệ lô hàng Styx Brew.'
        mock_http.return_value = (200, {"choices": [{"message": {"content": mock_resp}}]}, mock_resp, 120.0)
        res = psa.probe_translation_integrity("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "WARN")
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertEqual(res["reason_code"], "FORMAT_CORRUPTED")

    @patch("provider_security_auditor.execute_bounded_http")
    def test_probe_translation_integrity_altered_proper_noun(self, mock_http):
        mock_resp = 'Chào mừng đến với {0}, đặc vụ. Tập đoàn <color=#ffcc00>Titan Group</color> đã chỉ định Hắc Cẩu bảo vệ lô hàng Styx Brew cho %s.'
        mock_http.return_value = (200, {"choices": [{"message": {"content": mock_resp}}]}, mock_resp, 120.0)
        res = psa.probe_translation_integrity("https://test.com/v1", "sk-test", "model")
        self.assertEqual(res["status"], "WARN")
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["reason_code"], "PROPER_NOUN_ALTERED")


if __name__ == "__main__":
    unittest.main()
