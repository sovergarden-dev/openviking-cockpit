//! Taxonomy V3.1 security audit cache reader and presentation sanitizer (`audit_<scope_id>.json`).
//! Matches `monitor/provider_security_auditor.py` scope hashing byte-for-byte.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::conf_gate::{display_clean_path, CachedAuditVerdict};
use crate::config::safe_write::sha256_hex;
use crate::services::auditor::{
    evaluate_v31_decision, probe_tier, AuditReportDocument, ProbeRow, SecurityLatch,
};

pub const CLASSIFIER_VERSION: &str = "3.1.0";
pub const PROBE_VERSION: &str = "synthetic-probes-2";
pub const POLICY_VERSION: &str = "v31-integration-2";
pub const REPORT_VERSION: &str = "audit-report-2";
pub const REPORT_MAX_BYTES: usize = 1_048_576;

static SECRET_REDACT_RE: OnceLock<Regex> = OnceLock::new();

fn secret_regex() -> &'static Regex {
    SECRET_REDACT_RE.get_or_init(|| {
        Regex::new(r#"(?i)(\b(?:api[_-]?key|token|access_token|auth_token|secret|password)\b["']?\s*[=:]\s*|bearer\s+)(["']?)([^\s"']+)"#).unwrap()
    })
}

/// Strips ANSI escapes, dangerous control characters, BiDi overrides, and masks bearer/secret tokens.
pub fn presentation_sanitize_text(raw: &str, known_secret: Option<&str>) -> String {
    let mut text = if let Some(sec) = known_secret.filter(|s| !s.is_empty()) {
        raw.replace(sec, "[REDACTED]")
    } else {
        raw.to_string()
    };

    // Strip dangerous control chars (except \t, \n, \r), BiDi overrides, and zero-width chars.
    text = text
        .chars()
        .filter(|&c| {
            let u = c as u32;
            let ctrl =
                (u < 0x20 && c != '\t' && c != '\n' && c != '\r') || (0x7F..=0x9F).contains(&u);
            let bidi = (0x202A..=0x202E).contains(&u) || (0x2066..=0x2069).contains(&u);
            let zw = (0x200B..=0x200D).contains(&u) || u == 0xFEFF;
            !ctrl && !bidi && !zw
        })
        .collect();

    let masked = secret_regex()
        .replace_all(&text, "${1}${2}[REDACTED]")
        .into_owned();

    if masked.len() > REPORT_MAX_BYTES {
        let mut cut = REPORT_MAX_BYTES;
        while !masked.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}[OMITTED:LIMIT]", &masked[..cut])
    } else {
        masked
    }
}

fn ascii_escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{:04x}", unit));
            }
        }
    }
    out
}

pub fn safe_audit_endpoint(url: &str) -> Option<String> {
    if url.contains('?') || url.contains('#') {
        return None;
    }
    let parsed = reqwest::Url::parse(url.trim()).ok()?;
    let scheme = parsed.scheme();
    let host = parsed.host_str()?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
    if scheme != "https" && !(scheme == "http" && is_loopback) {
        return None;
    }
    let clean_path = parsed.path().trim_end_matches('/');
    let host_fmt = if host == "::1" { "[::1]" } else { host };
    let authority = match (scheme, parsed.port()) {
        ("https", None | Some(443)) => host_fmt.to_string(),
        ("http", None | Some(80)) => host_fmt.to_string(),
        (_, Some(p)) => format!("{}:{}", host_fmt, p),
        (_, None) => host_fmt.to_string(),
    };
    Some(format!("{}://{}{}", scheme, authority, clean_path))
}

/// Computes the exact `audit_<scope_id>.json` cache key matching Python `_cache_scope` + `_scope_id`.
pub fn compute_audit_scope_id(
    api_base: &str,
    model: &str,
    api_key: &str,
) -> Option<(String, BTreeMap<String, String>)> {
    if model.is_empty()
        || model.len() > 8192
        || model != model.trim()
        || model
            .chars()
            .any(|c| (c as u32) < 32 || (127..=159).contains(&(c as u32)))
    {
        return None;
    }
    let endpoint = safe_audit_endpoint(api_base)?;
    let mut cred_input = b"ov-audit-credential-v1\0".to_vec();
    cred_input.extend_from_slice(api_key.as_bytes());
    let cred_digest = sha256_hex(&cred_input);

    let mut scope = BTreeMap::new();
    scope.insert(
        "classifier_version".to_string(),
        CLASSIFIER_VERSION.to_string(),
    );
    scope.insert("credential_digest".to_string(), cred_digest);
    scope.insert("endpoint".to_string(), endpoint);
    scope.insert("model".to_string(), model.to_string());
    scope.insert("policy_version".to_string(), POLICY_VERSION.to_string());
    scope.insert("probe_version".to_string(), PROBE_VERSION.to_string());
    scope.insert("report_version".to_string(), REPORT_VERSION.to_string());

    let compact_utf8 = serde_json::to_string(&scope).ok()?;
    let compact_ascii = ascii_escape_json_str(&compact_utf8);
    let scope_id = sha256_hex(compact_ascii.as_bytes());
    Some((scope_id, scope))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReportSummaryView {
    pub scope_id: String,
    pub endpoint: String,
    pub model: String,
    pub report_age_s: f64,
    pub verdict_level: u8,
    pub memory_permitted: bool,
    pub safety_stop: bool,
    pub why: String,
}

/// Reads and validates a cached Taxonomy V3.1 report from `reports_dir/audit_<scope_id>.json`.
pub fn load_cached_audit_verdict(
    reports_dir: &Path,
    api_base: &str,
    model: &str,
    api_key: &str,
    max_age_s: f64,
) -> Option<CachedAuditVerdict> {
    let (scope_id, expected_scope) = compute_audit_scope_id(api_base, model, api_key)?;
    let file_path = reports_dir.join(format!("audit_{}.json", scope_id));
    let mut file = fs::File::open(&file_path).ok()?;
    let mut buf = Vec::new();
    file.by_ref()
        .take((REPORT_MAX_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > REPORT_MAX_BYTES {
        return None;
    }

    let doc: Value = serde_json::from_slice(&buf).ok()?;
    let obj = doc.as_object()?;

    let disk_scope: BTreeMap<String, String> =
        serde_json::from_value(obj.get("cache_scope")?.clone()).ok()?;
    if disk_scope != expected_scope {
        return None;
    }

    let target = obj.get("target")?.as_object()?;
    if target.get("api_base")?.as_str()? != expected_scope.get("endpoint")?.as_str()
        || target.get("model")?.as_str()? != model
    {
        return None;
    }

    let epoch_ts = obj.get("epoch_ts")?.as_f64()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .ok()?;
    if !epoch_ts.is_finite() || epoch_ts <= 0.0 || epoch_ts > now + 5.0 {
        return None;
    }
    let age_s = (now - epoch_ts).max(0.0);
    if age_s > max_age_s {
        return None;
    }

    let verdict = obj.get("verdict")?.as_object()?;
    let mut rows: Vec<ProbeRow> = serde_json::from_value(obj.get("results")?.clone()).ok()?;
    if rows.is_empty() {
        return None;
    }
    for r in &mut rows {
        if let Some(t) = probe_tier(&r.id) {
            r.tier = t;
        }
    }
    let expected = evaluate_v31_decision(&rows, &mut SecurityLatch::default());
    let level = verdict.get("verdict_level")?.as_u64()? as u8;
    let memory_permitted = verdict.get("memory_permitted")?.as_bool()?;
    let safety_stop = verdict.get("safety_stop")?.as_bool()?;
    if level != expected.level
        || memory_permitted != expected.memory_allowed
        || safety_stop != expected.safety_stop
    {
        return None;
    }
    if let Some(reason) = verdict.get("v31_decision_reason").and_then(|v| v.as_str()) {
        if reason != expected.reason.as_str() {
            return None;
        }
    }
    let raw_why = verdict.get("why").and_then(|v| v.as_str()).unwrap_or("");
    let why = presentation_sanitize_text(raw_why, Some(api_key));

    Some(CachedAuditVerdict {
        report_age_s: age_s,
        verdict_level: level,
        memory_permitted,
        safety_stop,
        why,
    })
}

/// Loads and validates a full cached `AuditReportDocument` (compatible with both Python and Rust reports)
/// so the 3-tab Audit Modal can open instantly without spending probe tokens when a report is still fresh.
pub fn load_cached_audit_document(
    reports_dir: &Path,
    api_base: &str,
    model: &str,
    api_key: &str,
    max_age_s: f64,
) -> Option<AuditReportDocument> {
    let (scope_id, expected_scope) = compute_audit_scope_id(api_base, model, api_key)?;
    let file_path = reports_dir.join(format!("audit_{}.json", scope_id));
    let mut file = fs::File::open(&file_path).ok()?;
    let mut buf = Vec::new();
    file.by_ref()
        .take((REPORT_MAX_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > REPORT_MAX_BYTES {
        return None;
    }

    let mut doc: AuditReportDocument = serde_json::from_slice(&buf).ok()?;
    if doc.results.is_empty() {
        return None;
    }
    if doc.cache_scope.as_ref()? != &expected_scope {
        return None;
    }
    if doc.target.get("api_base")?.as_str() != expected_scope.get("endpoint")?.as_str()
        || doc.target.get("model")?.as_str() != model
    {
        return None;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .ok()?;
    if !doc.epoch_ts.is_finite() || doc.epoch_ts <= 0.0 || doc.epoch_ts > now + 5.0 {
        return None;
    }
    let age_s = (now - doc.epoch_ts).max(0.0);
    if age_s > max_age_s {
        return None;
    }

    for row in &mut doc.results {
        if row.name.is_empty() {
            row.name = row.id.clone();
        }
        if let Some(t) = probe_tier(&row.id) {
            row.tier = t;
        }
        row.summary = presentation_sanitize_text(&row.summary, Some(api_key));
        row.evidence = presentation_sanitize_text(&row.evidence, Some(api_key));
        for f in &mut row.findings {
            *f = presentation_sanitize_text(f, Some(api_key));
        }
    }

    let expected = evaluate_v31_decision(&doc.results, &mut SecurityLatch::default());
    let level = doc.verdict.get("verdict_level")?.as_u64()? as u8;
    let memory_permitted = doc.verdict.get("memory_permitted")?.as_bool()?;
    let safety_stop = doc.verdict.get("safety_stop")?.as_bool()?;
    if level != expected.level
        || memory_permitted != expected.memory_allowed
        || safety_stop != expected.safety_stop
    {
        return None;
    }
    if let Some(reason) = doc
        .verdict
        .get("v31_decision_reason")
        .and_then(|v| v.as_str())
    {
        if reason != expected.reason.as_str() {
            return None;
        }
    }

    for v in doc.verdict.values_mut() {
        if let Value::String(s) = v {
            *s = presentation_sanitize_text(s, Some(api_key));
        }
    }

    doc.verdict
        .insert("from_cache".to_string(), Value::Bool(true));
    doc.verdict.insert(
        "report_age_s".to_string(),
        serde_json::json!(age_s.round() as u64),
    );
    doc.saved_report_file = Some(display_clean_path(&file_path));
    Some(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn test_presentation_sanitizer_masks_bearer_and_preserves_max_tokens() {
        let raw = "Authorization: Bearer SYNTHETIC_BEARER_XYZ123, max_tokens: 2048, api_key=SYNTHETIC_KEY_999\x00\u{202E}";
        let clean = presentation_sanitize_text(raw, Some("SYNTHETIC_KEY_999"));
        assert!(!clean.contains("SYNTHETIC_BEARER_XYZ123"));
        assert!(!clean.contains("SYNTHETIC_KEY_999"));
        assert!(!clean.contains('\x00'));
        assert!(!clean.contains('\u{202E}'));
        assert!(clean.contains("max_tokens: 2048"));
        assert!(clean.contains("[REDACTED]"));
    }

    #[test]
    fn test_cached_audit_report_roundtrip_and_tamper_rejection() {
        let dir = tempdir().expect("tempdir");
        let base = "https://api.example.com/v1/";
        let model = "gpt-test-v1";
        let key = "SYNTHETIC_AUDIT_KEY_777";

        let (scope_id, scope) = compute_audit_scope_id(base, model, key).expect("scope");
        assert_eq!(
            scope_id,
            "d2fb779a43bcb77a318f1368a21d930c1250c869fbf05d1c99f82c1e5746c740"
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let report = json!({
            "cache_scope": scope,
            "target": {
                "api_base": "https://api.example.com/v1",
                "model": model
            },
            "epoch_ts": now - 60.0,
            "verdict": {
                "verdict_level": 5,
                "v31_decision_reason": "VERIFIED_FAST",
                "memory_permitted": true,
                "safety_stop": false,
                "why": "Tier 0 clean"
            },
            "results": [
                {"id": "transport_routing", "status": "PASS"},
                {"id": "ansi_control_hygiene", "status": "PASS"},
                {"id": "tool_call_hijack", "status": "PASS"},
                {"id": "canary_isolation", "status": "PASS"},
                {"id": "strict_json_vlm", "status": "PASS"},
                {"id": "prompt_boundary", "status": "PASS"},
                {"id": "operational_latency", "status": "PASS", "latency_ms": 420.0}
            ]
        });
        let path = dir.path().join(format!("audit_{}.json", scope_id));
        fs::write(&path, serde_json::to_vec(&report).unwrap()).expect("write report");

        let loaded = load_cached_audit_verdict(dir.path(), base, model, key, 86_400.0)
            .expect("load valid report");
        assert_eq!(loaded.verdict_level, 5);
        assert!(loaded.memory_permitted);
        assert!(!loaded.safety_stop);

        // Full document loader must also accept Python-style ProbeRow (without reason_code)
        let full_doc = load_cached_audit_document(dir.path(), base, model, key, 86_400.0)
            .expect("load full cached document");
        assert_eq!(
            full_doc.verdict.get("from_cache").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(full_doc.results.len(), 7);
        assert_eq!(full_doc.results[0].id, "transport_routing");

        // Wrong API key must miss cache
        assert!(
            load_cached_audit_verdict(dir.path(), base, model, "DIFFERENT_KEY", 86_400.0).is_none()
        );

        // Forged verdict_level inconsistent with incomplete/failed results must be rejected
        let mut tampered = report.clone();
        tampered["results"] = json!([{"id": "transport_routing", "status": "PASS"}]);
        fs::write(&path, serde_json::to_vec(&tampered).unwrap()).expect("write tampered report");
        assert!(load_cached_audit_verdict(dir.path(), base, model, key, 86_400.0).is_none());
        assert!(load_cached_audit_document(dir.path(), base, model, key, 86_400.0).is_none());
    }
}
