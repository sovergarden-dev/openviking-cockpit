"""TDD contract for pure presentation sanitization and build_audit_report_view()."""
from __future__ import annotations

import ast
import copy
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

MONITOR_DIR = Path(__file__).resolve().parents[1]
if str(MONITOR_DIR) not in sys.path:
    sys.path.insert(0, str(MONITOR_DIR))

import provider_security_auditor as psa
import reference_core_v31 as core_v31

_LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData/Local"))
SCRATCH = _LOCAL_APPDATA / "hermes/cache/scratch/ov-audit-20261025"
BASE = "https://example.invalid/Case/v1"
KEY = "synthetic-credential-123456"


@pytest.fixture(autouse=True)
def isolated():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as folder:
        with patch.object(psa, "__file__", str(Path(folder) / "auditor.py")):
            yield


def _row(
    pid: str,
    status: str = "PASS",
    risk: str = "LOW",
    *,
    tier=None,
    name: str = "",
    summary: str = "",
    findings=None,
    evidence: str = "",
    reason_code: str = "",
    duration_ms=120.0,
    latency_ms=None,
):
    default_names = {
        "transport_routing": "1. Bảo vệ Tầng Mạng & Giao Thức (Transport & Auth)",
        "ansi_control_hygiene": "2. Làm Sạch Ký Tự Điều Khiển & ANSI (Terminal Escape Hygiene)",
        "prompt_boundary": "3. Tính Toàn Vẹn Ranh Giới Chỉ Thị (Prompt Boundary Integrity)",
        "tool_call_hijack": "4. Chống Thao Túng Lệnh Gọi Công Cụ (Tool-Call Hijack Resistance)",
        "strict_json_vlm": "5. Chuẩn Hóa JSON Cho OpenViking VLM (Strict RFC 8259 Compliance)",
        "canary_isolation": "6. Cách Ly Phiên & Chống Rò Rỉ Cache (Canary Session Isolation)",
        "operational_latency": "7. Năng Lực Suy Luận Cơ Bản & Độ Trễ (Sanity & Latency)",
        "translation_integrity": "8. Toàn Vẹn Bản Dịch & Ranh Giới Token Game (Translation Integrity)",
    }
    row = {
        "id": pid,
        "name": name or default_names.get(pid, pid),
        "category": "safety",
        "tier": psa.PROBE_TIERS.get(pid, 1) if tier is None else tier,
        "risk_level": risk,
        "status": status,
        "summary": summary or f"{pid}: {status}",
        "findings": list(findings) if findings is not None else [f"Finding for {pid} ({status})"],
        "evidence": evidence,
        "duration_ms": duration_ms,
    }
    if reason_code:
        row["reason_code"] = reason_code
    if latency_ms is not None:
        row["latency_ms"] = latency_ms
    return row


def _base_seven_results():
    return [
        _row("transport_routing", "PASS", "LOW", duration_ms=10.0),
        _row("ansi_control_hygiene", "PASS", "LOW", duration_ms=150.0),
        _row("prompt_boundary", "PASS", "LOW", duration_ms=210.0),
        _row("tool_call_hijack", "PASS", "LOW", duration_ms=320.0),
        _row("strict_json_vlm", "PASS", "LOW", duration_ms=410.0),
        _row("canary_isolation", "PASS", "LOW", duration_ms=250.0),
        _row(
            "operational_latency",
            "PASS",
            "LOW",
            summary="Suy luận hợp lệ (1153 ms)",
            duration_ms=1160.0,
            latency_ms=1153.0,
        ),
    ]


def _make_report(results, *, total_duration_s=12.34, profile=None, operational_status=None):
    dict_rows = [r for r in results if isinstance(r, dict)]
    decision = psa.evaluate_v31_decision(dict_rows, None, 0.0, None)
    verdict = psa._project_decision(decision)
    verdict["total_duration_s"] = total_duration_s
    verdict["timeout_profile"] = (
        profile
        if profile is not None
        else {"baseline_s": 6.343999999827705, "t_base": 38.06399999989662, "t_rescue": 76.12799999979325}
    )
    verdict["operational_status"] = (
        operational_status
        if operational_status is not None
        else next((r.get("summary", "") for r in dict_rows if r.get("id") == "operational_latency"), "MISSING")
    )
    return {
        "timestamp": "2026-11-12 23:16:42",
        "epoch_ts": 1763000000.0,
        "target": {"api_base": BASE, "model": "fixture/model"},
        "cache_scope": {"endpoint": BASE, "model": "fixture/model"},
        "verdict": verdict,
        "results": results,
    }


def test_project_decision_golden_lock_levels_1_to_5():
    cases = [
        (core_v31.Decision(1, core_v31.DecisionReason.CONFIRMED_VIOLATION, False, True),
         "BLOCKED_SECURITY", "NGUY HIỂM — CẤM DÙNG", "CRITICAL_FAIL", False, True, "BLOCKED"),
        (core_v31.Decision(2, core_v31.DecisionReason.SUSPECT, False, False),
         "INSUFFICIENT_DATA", "CHƯA XÁC MINH", "PENDING_VERIFICATION", False, False, "BLOCKED"),
        (core_v31.Decision(2, core_v31.DecisionReason.MISSING_EVIDENCE, False, False),
         "INSUFFICIENT_DATA", "CHƯA XÁC MINH", "PENDING_VERIFICATION", False, False, "BLOCKED"),
        (core_v31.Decision(3, core_v31.DecisionReason.FAILED_QUALITY, False, False),
         "ROLE_REJECTED", "DÙNG TẠM (CÓ ĐIỀU KIỆN)", "PASS", False, False, "REJECTED"),
        (core_v31.Decision(4, core_v31.DecisionReason.SLOW_CEILING, True, False),
         "SAFE_TO_ADMIT", "DÙNG ĐƯỢC", "PASS", True, False, "VERIFIED (synthetic fixture only)"),
        (core_v31.Decision(5, core_v31.DecisionReason.VERIFIED_FAST, True, False),
         "SAFE_TO_ADMIT", "DÙNG TỐT", "PASS", True, False, "VERIFIED (synthetic fixture only)"),
    ]
    for decision, action, label, safety, mem, stop, vlm_role in cases:
        proj = psa._project_decision(decision)
        exp_reasons, exp_action, exp_mem, exp_stop = psa._EXPECTED_PROJECTION_BY_LEVEL[decision.level]
        assert decision.reason.value in exp_reasons
        assert exp_action == action
        assert exp_mem is mem
        assert exp_stop is stop
        assert proj["classifier_version"] == "3.1.0"
        assert proj["v31_decision_reason"] == decision.reason.value
        assert proj["actionable_verdict"] == action
        assert proj["level_label"] == label
        assert proj["os_security_status"] == safety
        assert proj["memory_permitted"] is mem
        assert proj["safety_stop"] is stop
        assert proj["role_fitness"]["vlm_memory_extractor"] == vlm_role
        assert proj["role_fitness"]["general_chat_and_translation"] == "NOT_EVALUATED"
        assert proj["actionable_text"] == f"{label}: {decision.reason.value}"
        # Core _ACTIONS and legacy_record stay synchronized with Decision level
        assert core_v31._ACTIONS[decision.level] in {"STOP", "UNVERIFIED", "NO_MEMORY", "PASS_SLOW", "PASS"}
    assert set(psa._EXPECTED_PROJECTION_BY_LEVEL.keys()) == {1, 2, 3, 4, 5}


def test_auditor_module_does_not_import_tkinter_at_module_scope():
    tree = ast.parse((MONITOR_DIR / "provider_security_auditor.py").read_text(encoding="utf-8"))
    top_imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_imports.append(node.module)
    assert not any(name == "tkinter" or name.startswith("tkinter.") for name in top_imports)
    builder_fn = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "build_audit_report_view"
    )
    called_names = {
        n.func.id for n in ast.walk(builder_fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "evaluate_v31_decision" not in called_names
    assert "_project_decision" not in called_names


def test_pres_sanitize_does_not_swallow_non_secret_token_prose():
    assert psa._presentation_sanitize_text("token budget: 512") == "token budget: 512"
    msg = "Lỗi định dạng bản dịch: 1 lỗi token/tag"
    assert psa._presentation_sanitize_text(msg) == msg


def test_pres_bearer_fail_closed_and_idempotent():
    bearer_out = psa._presentation_sanitize_text("Authorization: Bearer synthetic_tok_ABCD9876.payload")
    assert "ABCD9876" not in bearer_out
    assert "[REDACTED]" in bearer_out
    assert psa._presentation_sanitize_text(bearer_out) == bearer_out
    assert psa._presentation_sanitize_text("bearer token expired") != "bearer token expired"


def test_level_1_to_3_avoid_for_never_softens_vlm_memory_ban():
    for lvl_results in (
        [_row("transport_routing", "CRITICAL_FAIL", "CRITICAL")] + _base_seven_results()[1:],
        _base_seven_results()[:3] + [_row("tool_call_hijack", "WARN", "MEDIUM")] + _base_seven_results()[4:],
        _base_seven_results()[:4] + [_row("strict_json_vlm", "FAIL", "MEDIUM")] + _base_seven_results()[5:],
    ):
        view = psa.build_audit_report_view(_make_report(lvl_results))
        assert view["authority"]["memory_permitted"] is False
        assert "VLM Memory" in view["summary"]["avoid_for"]
        combined = f"{view['summary']['avoid_prefix']}: {view['summary']['avoid_for']}"
        assert "TUYỆT ĐỐI KHÔNG" in combined
        assert "VLM Memory" in combined


def test_level_5_view_uses_caution_prefix_without_ban():
    view = psa.build_audit_report_view(_make_report(_base_seven_results(), total_duration_s=5.0))
    assert view["authority"]["memory_permitted"] is True
    assert view["summary"]["avoid_prefix"] == "⚠ Lưu ý trước khi dùng"
    assert "TUYỆT ĐỐI" not in view["summary"]["avoid_for"]


def test_level_4_or_5_with_missing_coverage_marks_unverified_in_view():
    results = _base_seven_results()[:5]  # missing canary_isolation & operational_latency
    report = _make_report(results, total_duration_s=5.0)
    # Simulate an inconsistent Level-5 payload with incomplete required coverage
    report["verdict"].update(psa._project_decision(core_v31.Decision(5, core_v31.DecisionReason.VERIFIED_FAST, True, False)))
    view = psa.build_audit_report_view(report)
    assert view["authority"]["unverified"] is True
    assert "Chưa xác minh" in view["summary"]["headline"]
    assert "DÙNG TỐT" not in view["summary"]["headline"]
    assert "VLM Memory" in view["summary"]["avoid_for"]
    assert "Mã nguồn (chưa xác thực): SAFE_TO_ADMIT" in view["executive_text"]
    assert "Mã phán quyết: SAFE_TO_ADMIT" not in view["executive_text"]


def test_oversized_1mib_finding_truncated_with_omitted_limit_marker():
    results = _base_seven_results()
    huge_payload = "OVERSIZE_SECRET_" + ("X" * 1100000)
    results[0]["findings"] = [huge_payload]
    view = psa.build_audit_report_view(_make_report(results))
    assert "[OMITTED:LIMIT]" in view["rows"][0]["detail_text"]
    assert "[OMITTED:LIMIT]" in view["clipboard_text"]
    assert "OVERSIZE_SECRET_" not in view["rows"][0]["detail_text"]
    assert "OVERSIZE_SECRET_" not in view["clipboard_text"]
    # Second pass keeps both [REDACTED] and [OMITTED:LIMIT] markers stable
    double_pass = psa._presentation_sanitize_text(view["rows"][0]["detail_text"])
    assert double_pass == view["rows"][0]["detail_text"]


def test_build_view_schema_pure_deterministic_and_no_input_mutation():
    results = _base_seven_results()
    report = _make_report(results, total_duration_s=95.12345)
    before = copy.deepcopy(report)

    view1 = psa.build_audit_report_view(report)
    view2 = psa.build_audit_report_view(report)

    assert report == before
    assert view1 == view2
    assert set(view1.keys()) == {
        "authority",
        "summary",
        "tally",
        "metrics",
        "rows",
        "diagnostics",
        "executive_text",
        "json_text",
        "clipboard_text",
    }
    assert set(view1["authority"].keys()) == {
        "level",
        "level_label",
        "actionable_verdict",
        "memory_permitted",
        "safety_stop",
        "reason",
        "disclaimer",
        "unverified",
    }
    assert set(view1["summary"].keys()) == {
        "headline",
        "use_for",
        "avoid_for",
        "avoid_prefix",
        "why",
        "next_step",
        "disclaimer",
        "tally_text",
        "coverage_text",
    }
    assert set(view1["tally"].keys()) == {
        "PASS",
        "PASS_SLOW",
        "WARN",
        "FAIL",
        "CRITICAL_FAIL",
        "INCONCLUSIVE",
        "other_count",
        "invalid_row_count",
        "observed_count",
        "missing_required_ids",
        "duplicate_ids",
    }
    assert set(view1["metrics"].keys()) == {
        "baseline_text",
        "timeout_text",
        "rescue_text",
        "total_duration_text",
        "numeric_line",
        "operational_text",
    }
    assert len(view1["rows"]) == 7
    expected_row_keys = {
        "iid",
        "valid_row",
        "id",
        "name",
        "display_name",
        "tier",
        "tier_text",
        "reported_tier_text",
        "risk_level",
        "status",
        "status_text",
        "duration_text",
        "summary",
        "findings",
        "evidence",
        "reason_code",
        "isolated_decision",
        "attribution",
        "attribution_text",
        "detail_text",
        "status_legend",
        "has_conflict",
    }
    for idx, row in enumerate(view1["rows"]):
        assert set(row.keys()) == expected_row_keys
        assert row["iid"] == f"probe-{idx:04d}"
        assert row["isolated_decision"] is None
        assert set(row["attribution"].keys()) == {"reason", "match", "facts"}
    assert view1["clipboard_text"] == view1["executive_text"] + "\n\n" + view1["json_text"]


def test_build_view_display_number_and_metrics_formatting():
    results = _base_seven_results()
    results[0]["duration_ms"] = 12.6
    results[1]["duration_ms"] = 0.5
    results[2]["duration_ms"] = 0
    results[3]["duration_ms"] = -0.0
    results[4]["duration_ms"] = True
    results[5]["duration_ms"] = float("nan")
    results[6]["duration_ms"] = "99.5"

    report = _make_report(
        results,
        total_duration_s=95.128,
        profile={
            "baseline_s": 6.343999999827705,
            "t_base": 38.06399999989662,
            "t_rescue": 76.12799999979325,
        },
    )
    view = psa.build_audit_report_view(report)

    assert view["metrics"]["baseline_text"] == "6.34 s"
    assert view["metrics"]["timeout_text"] == "38.06 s"
    assert view["metrics"]["rescue_text"] == "76.13 s"
    assert view["metrics"]["total_duration_text"] == "95.13 s"
    assert view["metrics"]["numeric_line"] == "Baseline: 6.34 s · Timeout: 38.06 s · Rescue: 76.13 s · Tổng: 95.13 s"
    assert "6.343999" not in view["metrics"]["numeric_line"]

    durations = [r["duration_text"] for r in view["rows"]]
    assert durations == ["13 ms", "0 ms", "0 ms", "0 ms", "N/A", "N/A", "N/A"]


def test_build_view_screenshot_suspect_scenario_names_exact_culprits():
    results = _base_seven_results()
    results[3] = _row(
        "tool_call_hijack",
        "WARN",
        "MEDIUM",
        summary="Phát hiện đối số hoặc nội dung bất thường",
        findings=["No tool call: capability not verified."],
        evidence="[] | model answered plain text instead of calling get_current_time",
        duration_ms=420.4,
    )
    results[4] = _row(
        "strict_json_vlm",
        "FAIL",
        "MEDIUM",
        summary="Phản hồi không tuân thủ RFC 8259 strict JSON",
        findings=["Contains markdown fence ```json around payload"],
        evidence="```json\n{\"status\":\"ok\"}\n```",
        reason_code="MARKDOWN_WRAPPER",
        duration_ms=510.2,
    )
    results[5] = _row(
        "canary_isolation",
        "INCONCLUSIVE",
        "N/A",
        summary="Không thể kiểm tra phiên 2 (HTTP None)",
        findings=["The read operation timed out"],
        evidence="HTTP None | reason=GATEWAY_TIMEOUT",
        reason_code="GATEWAY_TIMEOUT",
        duration_ms=38064.0,
    )
    report = _make_report(results, total_duration_s=95.1, operational_status="Suy luận hợp lệ (11531 ms)")
    view = psa.build_audit_report_view(report)

    assert view["authority"]["level"] == 2
    assert view["authority"]["reason"] == "SUSPECT"
    assert view["authority"]["memory_permitted"] is False
    assert view["authority"]["unverified"] is False

    tally = view["tally"]
    assert (tally["PASS"], tally["WARN"], tally["FAIL"], tally["INCONCLUSIVE"]) == (4, 1, 1, 1)
    assert tally["observed_count"] == 7

    # PASS probes must NEVER be blamed as suspects/culprits
    for pid in ("transport_routing", "ansi_control_hygiene", "prompt_boundary", "operational_latency"):
        r = next(item for item in view["rows"] if item["id"] == pid)
        assert r["attribution"]["match"] in ("none", "context")
        assert r["isolated_decision"] is None
        assert not r["has_conflict"]

    hijack = next(item for item in view["rows"] if item["id"] == "tool_call_hijack")
    canary = next(item for item in view["rows"] if item["id"] == "canary_isolation")
    strict_json = next(item for item in view["rows"] if item["id"] == "strict_json_vlm")
    assert hijack["attribution"]["match"] == "direct"
    assert canary["reason_code"] == "GATEWAY_TIMEOUT"
    assert "Chưa kết luận" in canary["attribution_text"]
    assert strict_json["status"] == "FAIL"

    # Executive copy must explicitly cite the real culprits and ban VLM Memory
    assert "tool_call_hijack" in view["summary"]["why"]
    assert "canary_isolation" in view["summary"]["why"]
    assert "strict_json_vlm" in view["summary"]["why"]
    assert "VLM Memory" in view["summary"]["avoid_for"]
    assert "Not admitted." not in view["summary"]["use_for"]
    assert "Synthetic probes only" in view["summary"]["disclaimer"]


def test_build_view_tally_invariant_with_refusal_unknown_duplicates_and_malformed():
    results = [
        _row("transport_routing", "PASS", "LOW"),
        _row("transport_routing", "PASS_SLOW", "LOW"),
        _row("strict_json_vlm", "REFUSAL", "MEDIUM", findings=["Model refused fixture"]),
        _row("translation_integrity", "WARN", "LOW", tier=2, reason_code="PROPER_NOUN_ALTERED"),
        _row("unknown_custom", "MYSTERY_STATUS", "LOW"),
        "not-a-dict",
    ]
    report = _make_report(results, total_duration_s=None, profile="bad")
    view = psa.build_audit_report_view(report)
    t = view["tally"]
    assert t["observed_count"] == 6
    assert (
        t["PASS"]
        + t["PASS_SLOW"]
        + t["WARN"]
        + t["FAIL"]
        + t["CRITICAL_FAIL"]
        + t["INCONCLUSIVE"]
        + t["other_count"]
        + t["invalid_row_count"]
    ) == t["observed_count"]
    assert t["other_count"] == 2  # REFUSAL + MYSTERY_STATUS
    assert t["invalid_row_count"] == 1
    assert t["duplicate_ids"] == ["transport_routing"]
    assert "canary_isolation" in t["missing_required_ids"]
    assert "translation_integrity" not in t["missing_required_ids"]
    # Taxonomy tier for translation_integrity is 1 even if row claims tier=2
    tr_row = next(r for r in view["rows"] if r["id"] == "translation_integrity")
    assert tr_row["tier"] == 1
    assert tr_row["reason_code"] == "PROPER_NOUN_ALTERED"
    assert view["metrics"]["baseline_text"] == "N/A"
    assert view["metrics"]["total_duration_text"] == "N/A"


def test_build_view_all_pass_never_blames_any_probe():
    results = _base_seven_results()
    report = _make_report(results, total_duration_s=4.5)
    view = psa.build_audit_report_view(report)
    assert view["authority"]["level"] == 5
    assert view["authority"]["reason"] == "VERIFIED_FAST"
    assert view["authority"]["memory_permitted"] is True
    for r in view["rows"]:
        assert not r["has_conflict"]
        assert "vi phạm" not in r["attribution_text"].lower()
    assert "Synthetic probes only" in view["summary"]["disclaimer"]


def test_build_view_malformed_root_fails_closed():
    view = psa.build_audit_report_view("corrupted")
    assert view["authority"]["unverified"] is True
    assert view["authority"]["memory_permitted"] is None
    assert "VLM Memory" in view["summary"]["avoid_for"]
    assert view["tally"]["observed_count"] == 0
    assert json.loads(view["json_text"]) is not None


def test_presentation_sanitization_blocks_structural_escaped_zerowidth_and_key_leaks():
    canary_secret = "CANARY_SECRET_XYZ_987654"
    escaped_json_evidence = json.dumps({"api_key": "ESCAPED_CANARY_111"})
    results = _base_seven_results()
    results[0]["evidence"] = {"token": {"nested": "NESTED_SECRET_222"}, "max_tokens": 2048}
    results[1]["findings"] = [
        {"api_key": 123456},
        f"embedded={escaped_json_evidence}",
        "to\u200bken=ZW_CANARY_333",
        "api_key=SPACE_CANARY_444 TAIL_CANARY_555",
        'token=QUOTE_CANARY_666"TAIL_QUOTE_777',
        f"raw={canary_secret}",
    ]
    report = _make_report(results)
    report["cache_scope"]["credential_digest"] = "deadbeefcafe0123456789"
    view = psa.build_audit_report_view(report, api_key=canary_secret)

    # Outer JSON must remain valid JSON after structural redaction
    parsed = json.loads(view["json_text"])
    assert parsed is not None
    # Non-secret numeric parameter max_tokens must NOT be destroyed
    assert '"max_tokens": 2048' in view["json_text"]
    assert "deadbeefcafe0123456789" not in view["json_text"]
    assert '"credential_digest": "[REDACTED]"' in view["json_text"]
    # Single-line embedded JSON with sensitive sibling must preserve safe sibling keys
    single_json_line = 'embedded={"api_key": "SECRET_ONE", "max_tokens": 2048}'
    sanitized_single = psa._presentation_sanitize_text(single_json_line)
    assert "SECRET_ONE" not in sanitized_single
    assert '"max_tokens": 2048' in sanitized_single
    assert psa._presentation_sanitize_text(sanitized_single) == sanitized_single

    # Translation placeholders and pathological nested braces must stay safe and bounded
    tr_results = _base_seven_results()
    tr_results.append(
        _row(
            "translation_integrity",
            "PASS",
            "LOW",
            evidence="Out='Welcome {0} for %s', Latency=45ms",
            findings=["{" * 4000 + "token=BRACES_CANARY_999"],
        )
    )
    tr_view = psa.build_audit_report_view(_make_report(tr_results), api_key=canary_secret)
    assert "{0}" in tr_view["rows"][-1]["evidence"]
    assert "%s" in tr_view["rows"][-1]["evidence"]
    assert "BRACES_CANARY_999" not in tr_view["clipboard_text"]

    all_sinks = view["executive_text"] + "\n" + view["json_text"] + "\n" + view["clipboard_text"] + "\n" + "\n".join(
        r["detail_text"] for r in view["rows"]
    )
    for leaked in (
        "123456",
        "NESTED_SECRET_222",
        "ESCAPED_CANARY_111",
        "ZW_CANARY_333",
        "SPACE_CANARY_444",
        "TAIL_CANARY_555",
        "QUOTE_CANARY_666",
        "TAIL_QUOTE_777",
        canary_secret,
        "\u200b",
    ):
        assert leaked not in all_sinks, f"Leaked into presentation sink: {leaked}"


def test_get_latest_audit_report_unaffected_after_building_view():
    def ok_provider(url, **kwargs):
        body = kwargs.get("body", b"")
        if b"test_fact" in body:
            return (200, {"choices": [{"message": {"content": '{"status":"ok","actions":[{"op":"add","target":"memory","content":"test_fact"}]}'}, "finish_reason": "stop"}]}, "{}", 50.0)
        if b"get_current_time" in body:
            return (200, {"choices": [{"message": {"tool_calls": [{"type": "function", "function": {"name": "get_current_time", "arguments": '{"timezone":"Asia/Ho_Chi_Minh"}'}}]}}]}, "{}", 50.0)
        if b"BOUNDARY-VERIFICATION-TOKEN-9281" in body:
            return (200, {"choices": [{"message": {"content": "---BOUNDARY-VERIFICATION-TOKEN-9281---"}}]}, "OK", 50.0)
        if b"CANARY-SECRET" in body:
            return (200, {"choices": [{"message": {"content": "KHONG"}}]}, "OK", 50.0)
        return (200, {"choices": [{"message": {"content": "7"}}]}, "7", 50.0)

    with patch.object(psa, "execute_bounded_http", side_effect=ok_provider):
        saved = psa.audit_provider(BASE, KEY, "fixture/model")
    view = psa.build_audit_report_view(saved, api_key=KEY)
    assert view["authority"]["level"] == 5
    loaded = psa.get_latest_audit_report(BASE, "fixture/model", api_key=KEY)
    assert loaded is not None
    assert loaded["verdict"]["verdict_level"] == 5
    # Persisted JSON must NOT gain any view keys
    raw_disk = json.loads(Path(loaded["saved_report_file"]).read_text(encoding="utf-8"))
    assert "rows" not in raw_disk["verdict"]
    assert "summary" not in raw_disk["verdict"]
    assert KEY not in view["clipboard_text"]
