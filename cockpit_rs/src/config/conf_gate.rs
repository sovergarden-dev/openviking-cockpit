//! Configuration gate, redacted slot summaries, drift check, and admission policy for OpenViking `ov.conf`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::safe_write::{sha256_hex, write_restricted_bytes_atomic, SafeWriteError};
use crate::secrets::secret_store::{
    get_env_var_name, resolve_secret, ResolvedSecret, SecretStatus,
};
use crate::services::auditor_cache::{inspect_cached_audit_badge, AuditBadgeStatus};
use crate::services::telemetry::VlmActiveResult;

pub const AUDIT_TTL_PRIMARY_S: f64 = 86_400.0;
pub const AUDIT_TTL_FAILOVER_S: f64 = 7.0 * 86_400.0;
pub const FAILBACK_REQUEST_COUNT_UNLIMITED: u32 = 2_147_483_647;

pub fn stored_failback_request_count(ui_value: u32) -> u32 {
    if ui_value == 0 {
        FAILBACK_REQUEST_COUNT_UNLIMITED
    } else {
        ui_value
    }
}

pub fn ui_failback_request_count(stored: Option<u32>) -> u32 {
    match stored {
        None | Some(0) => 0,
        Some(v) if v >= 2_000_000_000 => 0,
        Some(v) => v,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfGateError {
    #[error("Safe write error: {0}")]
    SafeWrite(#[from] SafeWriteError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration validation error: {0}")]
    Validation(String),

    #[error("Security audit required: {message}")]
    AuditRequired { message: String, slots: Vec<usize> },

    #[error("Revision mismatch for {file}: expected {expected}, found {actual}")]
    RevisionMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("Refusing to modify live configuration: {0}")]
    LivePathProtected(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVikingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlm: Option<VlmConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VlmCredentialSlot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl fmt::Debug for VlmCredentialSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlmCredentialSlot")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("api_base", &self.api_base)
            .field("api_key", &"[REDACTED]")
            .field("extra", &self.extra)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VlmConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub model: String,
    pub api_base: String,
    pub api_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failback_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failback_request_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<VlmCredentialSlot>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl fmt::Debug for VlmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlmConfig")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("api_base", &self.api_base)
            .field("api_key", &"[REDACTED]")
            .field("thinking", &self.thinking)
            .field("max_retries", &self.max_retries)
            .field("failback_timeout_seconds", &self.failback_timeout_seconds)
            .field("failback_request_count", &self.failback_request_count)
            .field("credentials", &self.credentials)
            .field("extra", &self.extra)
            .finish()
    }
}

/// Redacted IPC representation of a single routing slot (never contains raw `api_key`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSummary {
    pub slot_index: usize,
    pub id: String,
    pub role: String,
    pub provider: Option<String>,
    pub model: String,
    pub api_base: String,
    pub secret_status: SecretStatus,
    pub env_var_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_audit_level: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_audit_age_s: Option<u64>,
    #[serde(default)]
    pub cached_audit_expired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_audit_expired_level: Option<u8>,
    #[serde(default)]
    pub cached_audit_ttl_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotDriftStatus {
    pub drift: bool,
    pub reason: String,
}

/// Redacted IPC summary of `ov.conf`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSummary {
    pub conf_path: String,
    pub sha256: String,
    pub embedding_provider: Option<String>,
    pub embedding_model: Option<String>,
    pub embedding_api_base: Option<String>,
    pub embedding_dimension: Option<usize>,
    pub max_retries: Option<u32>,
    pub failback_timeout_seconds: Option<u64>,
    pub failback_request_count: u32,
    pub slots: Vec<SlotSummary>,
    pub drift: SlotDriftStatus,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SlotReorderOp {
    Swap { a: usize, b: usize },
    PromoteToPrimary { index: usize },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedAuditVerdict {
    pub report_age_s: f64,
    pub verdict_level: u8,
    pub memory_permitted: bool,
    pub safety_stop: bool,
    #[serde(default)]
    pub why: String,
}

#[derive(Clone, Deserialize)]
pub struct SlotUpdateInput {
    pub slot_index: usize,
    #[serde(default)]
    pub provider: Option<String>,
    pub model: String,
    pub api_base: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub allow_unaudited: bool,
    #[serde(default)]
    pub manual_save: bool,
}

impl fmt::Debug for SlotUpdateInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlotUpdateInput")
            .field("slot_index", &self.slot_index)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("api_base", &self.api_base)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("allow_unaudited", &self.allow_unaudited)
            .field("manual_save", &self.manual_save)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalSlotWarning {
    pub slot_index: usize,
    pub model: String,
    pub api_base: String,
    pub level: u8,
    pub why: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplySlotOutcome {
    pub new_sha256: String,
    pub backup_path: Option<String>,
    pub conditional_warnings: Vec<ConditionalSlotWarning>,
    pub slots: Vec<SlotSummary>,
}

/// Strips Windows `\\?\` verbatim prefixes before showing paths in UI payloads (`tauri.B8`).
pub fn display_clean_path(path: &Path) -> String {
    let raw = path.display().to_string();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", unc)
    } else if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        raw
    }
}

pub fn normalize_endpoint(base: &str) -> String {
    let trimmed = base.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(mut parsed) = reqwest::Url::parse(trimmed) {
        parsed.set_fragment(None);
        let clean_path = parsed.path().trim_end_matches('/').to_string();
        parsed.set_path(&clean_path);
        return parsed.to_string().trim_end_matches('/').to_string();
    }
    trimmed.trim_end_matches('/').to_string()
}

pub fn validate_endpoint_url(base: &str) -> Result<String, ConfGateError> {
    let trimmed = base.trim();
    let parsed = reqwest::Url::parse(trimmed).map_err(|_| {
        ConfGateError::Validation(format!("Invalid endpoint Base URL: '{}'", trimmed))
    })?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(ConfGateError::Validation(
            "Endpoint URL scheme must be http or https".to_string(),
        ));
    }
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfGateError::Validation(
            "Endpoint URL must not embed credentials, query parameters, or fragments".to_string(),
        ));
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

pub fn model_cache_key(base: &str, key_material: &str) -> String {
    format!(
        "{}#credential={}",
        normalize_endpoint(base),
        sha256_hex(key_material.as_bytes())
    )
}

pub fn credential_id(
    model: &str,
    base: &str,
    raw_key: &str,
    env_map: Option<&HashMap<String, String>>,
) -> String {
    let resolved = resolve_secret(raw_key, env_map);
    let material = if resolved.status == SecretStatus::SecretReady {
        resolved.value.clone()
    } else {
        format!("unresolved:{}", sha256_hex(raw_key.trim().as_bytes()))
    };
    let scope = format!("{}\0{}", model, model_cache_key(base, &material));
    let digest = sha256_hex(scope.as_bytes());
    format!("credential-{}", &digest[..32])
}

#[derive(Clone)]
struct EffectiveSlot {
    id: String,
    provider: Option<String>,
    model: String,
    api_base: String,
    raw_key: String,
}

impl EffectiveSlot {
    fn identity(&self, env_map: Option<&HashMap<String, String>>) -> (String, String) {
        let resolved = resolve_secret(&self.raw_key, env_map);
        let key_material = if resolved.status == SecretStatus::SecretReady {
            resolved.value.clone()
        } else {
            format!("unresolved:{}", sha256_hex(self.raw_key.trim().as_bytes()))
        };
        (
            self.model.clone(),
            model_cache_key(&self.api_base, &key_material),
        )
    }
}

fn extract_effective_slots(
    config: &OpenVikingConfig,
    env_map: Option<&HashMap<String, String>>,
) -> Vec<EffectiveSlot> {
    let Some(ref vlm) = config.vlm else {
        return Vec::new();
    };

    if let Some(ref creds) = vlm.credentials {
        if !creds.is_empty() {
            return creds
                .iter()
                .enumerate()
                .map(|(idx, c)| {
                    let model = c
                        .model
                        .clone()
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| {
                            if idx == 0 {
                                Some(vlm.model.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default();
                    let api_base = c
                        .api_base
                        .clone()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| vlm.api_base.clone());
                    let raw_key = c
                        .api_key
                        .clone()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| vlm.api_key.clone());
                    let id =
                        c.id.clone()
                            .filter(|s| !s.trim().is_empty())
                            .unwrap_or_else(|| credential_id(&model, &api_base, &raw_key, env_map));
                    EffectiveSlot {
                        id,
                        provider: c.provider.clone().or_else(|| vlm.provider.clone()),
                        model,
                        api_base,
                        raw_key,
                    }
                })
                .collect();
        }
    }

    vec![EffectiveSlot {
        id: "credential-0".to_string(),
        provider: vlm.provider.clone(),
        model: vlm.model.clone(),
        api_base: vlm.api_base.clone(),
        raw_key: vlm.api_key.clone(),
    }]
}

pub fn summarize_slots(
    config: &OpenVikingConfig,
    env_map: Option<&HashMap<String, String>>,
) -> Vec<SlotSummary> {
    summarize_slots_with_audits(config, env_map, None)
}

pub fn summarize_slots_with_audits(
    config: &OpenVikingConfig,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
) -> Vec<SlotSummary> {
    extract_effective_slots(config, env_map)
        .into_iter()
        .enumerate()
        .map(|(idx, s)| {
            let resolved = resolve_secret(&s.raw_key, env_map);
            let ttl = if idx == 0 {
                AUDIT_TTL_PRIMARY_S
            } else {
                AUDIT_TTL_FAILOVER_S
            };
            let badge = match (reports_dir, resolved.status) {
                (Some(dir), SecretStatus::SecretReady) => {
                    inspect_cached_audit_badge(dir, &s.api_base, &s.model, &resolved.value, ttl)
                }
                _ => AuditBadgeStatus {
                    ttl_s: ttl as u64,
                    ..AuditBadgeStatus::default()
                },
            };
            SlotSummary {
                slot_index: idx,
                id: s.id,
                role: if idx == 0 {
                    "primary".to_string()
                } else {
                    "fallback".to_string()
                },
                provider: s.provider,
                model: s.model,
                api_base: s.api_base,
                secret_status: resolved.status,
                env_var_name: get_env_var_name(&s.raw_key).or(resolved.env_var_name),
                cached_audit_level: badge.level,
                cached_audit_age_s: badge.age_s,
                cached_audit_expired: badge.expired,
                cached_audit_expired_level: badge.expired_level,
                cached_audit_ttl_s: badge.ttl_s,
            }
        })
        .collect()
}

/// Resolves `server.root_api_key` from `ov.conf` when configured and secret-ready.
pub fn resolve_server_root_api_key(
    config: &OpenVikingConfig,
    env_map: Option<&HashMap<String, String>>,
) -> Option<String> {
    let raw = config
        .extra
        .get("server")
        .and_then(|s| s.get("root_api_key"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let resolved = resolve_secret(raw, env_map);
    if resolved.status == SecretStatus::SecretReady && !resolved.value.is_empty() {
        Some(resolved.value)
    } else {
        None
    }
}

/// Resolves `(model, api_base, ResolvedSecret)` for an existing slot internally on the Rust backend.
pub fn resolve_slot_audit_target(
    config: &OpenVikingConfig,
    slot_index: usize,
    env_map: Option<&HashMap<String, String>>,
) -> Result<(String, String, ResolvedSecret), ConfGateError> {
    let (model, api_base, _raw, resolved) =
        resolve_slot_raw_credential(config, slot_index, env_map)?;
    Ok((model, api_base, resolved))
}

/// Resolves `(model, api_base, raw_key, ResolvedSecret)` for an existing slot strictly inside Rust backend memory.
pub fn resolve_slot_raw_credential(
    config: &OpenVikingConfig,
    slot_index: usize,
    env_map: Option<&HashMap<String, String>>,
) -> Result<(String, String, String, ResolvedSecret), ConfGateError> {
    let slots = extract_effective_slots(config, env_map);
    let slot = slots
        .get(slot_index)
        .ok_or_else(|| ConfGateError::Validation(format!("Slot {} out of range", slot_index)))?;
    let resolved = resolve_secret(&slot.raw_key, env_map);
    if resolved.status != SecretStatus::SecretReady {
        return Err(ConfGateError::Validation(format!(
            "Slot {} credential is not ready ({:?})",
            slot_index, resolved.status
        )));
    }
    Ok((
        slot.model.clone(),
        slot.api_base.clone(),
        slot.raw_key.clone(),
        resolved,
    ))
}

pub fn compute_slot_drift(
    slots: &[SlotSummary],
    live_vlm: Option<&VlmActiveResult>,
) -> SlotDriftStatus {
    let Some(live) = live_vlm else {
        return SlotDriftStatus {
            drift: false,
            reason: String::new(),
        };
    };
    let Some(ref live_ids) = live.credential_ids else {
        return SlotDriftStatus {
            drift: false,
            reason: String::new(),
        };
    };
    if live_ids.is_empty() {
        return SlotDriftStatus {
            drift: false,
            reason: String::new(),
        };
    }

    let mut conf_ids: Vec<String> = slots
        .iter()
        .map(|s| s.id.clone())
        .filter(|id| !id.is_empty())
        .collect();
    if conf_ids == vec!["default".to_string()] {
        conf_ids = vec!["credential-0".to_string()];
    }

    let count_mismatch = live.n.is_some_and(|n| n != slots.len());
    if count_mismatch || &conf_ids != live_ids {
        return SlotDriftStatus {
            drift: true,
            reason: "On-disk slot chain or priority order differs from the active server runtime."
                .to_string(),
        };
    }

    SlotDriftStatus {
        drift: false,
        reason: String::new(),
    }
}

pub fn summarize_config(
    conf_path: &Path,
    config: &OpenVikingConfig,
    sha256: &str,
    live_vlm: Option<&VlmActiveResult>,
    env_map: Option<&HashMap<String, String>>,
) -> ConfigSummary {
    summarize_config_with_audits(conf_path, config, sha256, live_vlm, env_map, None)
}

pub fn summarize_config_with_audits(
    conf_path: &Path,
    config: &OpenVikingConfig,
    sha256: &str,
    live_vlm: Option<&VlmActiveResult>,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
) -> ConfigSummary {
    let slots = summarize_slots_with_audits(config, env_map, reports_dir);
    let drift = compute_slot_drift(&slots, live_vlm);

    let dense = config
        .embedding
        .as_ref()
        .and_then(|e| e.get("dense").or(Some(e)));

    let embedding_provider = dense
        .and_then(|d| d.get("provider"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let embedding_model = dense
        .and_then(|d| d.get("model"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let embedding_api_base = dense
        .and_then(|d| d.get("api_base"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let embedding_dimension = dense
        .and_then(|d| d.get("dimension"))
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);

    ConfigSummary {
        conf_path: display_clean_path(conf_path),
        sha256: sha256.to_string(),
        embedding_provider,
        embedding_model,
        embedding_api_base,
        embedding_dimension,
        max_retries: config.vlm.as_ref().and_then(|v| v.max_retries),
        failback_timeout_seconds: config.vlm.as_ref().and_then(|v| v.failback_timeout_seconds),
        failback_request_count: ui_failback_request_count(
            config.vlm.as_ref().and_then(|v| v.failback_request_count),
        ),
        slots,
        drift,
    }
}

/// Validates candidate `after` configuration against `before` using the Slot Gatekeeper policy.
pub fn validate_conf_transition<F>(
    before: &OpenVikingConfig,
    after: &OpenVikingConfig,
    allow_unaudited: bool,
    manual_save: bool,
    env_map: Option<&HashMap<String, String>>,
    mut lookup_audit: F,
) -> Result<Vec<ConditionalSlotWarning>, ConfGateError>
where
    F: FnMut(&str, &str, &str) -> Option<CachedAuditVerdict>,
{
    let Some(ref after_vlm) = after.vlm else {
        return Err(ConfGateError::Validation(
            "Missing VLM configuration block".to_string(),
        ));
    };
    if after_vlm.api_key.trim().starts_with("dpapi:") {
        return Err(ConfGateError::Validation(
            "ov.conf cannot contain dpapi: encrypted envelopes; use ${ENV_VAR} or raw server credential".to_string(),
        ));
    }

    let after_slots = extract_effective_slots(after, env_map);
    if after_slots.is_empty() {
        return Err(ConfGateError::Validation(
            "At least one VLM routing slot is required".to_string(),
        ));
    }

    for (idx, slot) in after_slots.iter().enumerate() {
        if slot.model.trim().is_empty() {
            return Err(ConfGateError::Validation(format!(
                "Model name cannot be empty for slot {}",
                idx
            )));
        }
        validate_endpoint_url(&slot.api_base)?;
        if slot.raw_key.trim().starts_with("dpapi:") {
            return Err(ConfGateError::Validation(format!(
                "Slot {} contains dpapi: ciphertext, which OpenViking server cannot read directly",
                idx
            )));
        }
        let resolved = resolve_secret(&slot.raw_key, env_map);
        if resolved.status != SecretStatus::SecretReady {
            return Err(ConfGateError::Validation(format!(
                "API key for slot {} is missing or unresolved ({:?})",
                idx, resolved.status
            )));
        }
    }

    if manual_save {
        return Ok(Vec::new());
    }

    let before_slots = extract_effective_slots(before, env_map);
    let mut existing_all: HashSet<(String, String)> =
        before_slots.iter().map(|s| s.identity(env_map)).collect();
    let mut primary_before_ids: HashSet<(String, String)> = HashSet::new();
    if let Some(first) = before_slots.first() {
        primary_before_ids.insert(first.identity(env_map));
    }
    if let Some(ref b_vlm) = before.vlm {
        if !b_vlm.model.trim().is_empty() {
            let top = EffectiveSlot {
                id: String::new(),
                provider: b_vlm.provider.clone(),
                model: b_vlm.model.clone(),
                api_base: b_vlm.api_base.clone(),
                raw_key: b_vlm.api_key.clone(),
            };
            let id_pair = top.identity(env_map);
            primary_before_ids.insert(id_pair.clone());
            existing_all.insert(id_pair);
        }
    }

    let mut needs_audit_slots = Vec::new();
    let mut conditional = Vec::new();

    for (idx, slot) in after_slots.iter().enumerate() {
        let identity = slot.identity(env_map);
        if idx == 0 && primary_before_ids.contains(&identity) {
            continue;
        }
        if idx >= 1 && existing_all.contains(&identity) {
            continue;
        }

        let resolved = resolve_secret(&slot.raw_key, env_map);
        let max_ttl = if idx == 0 {
            AUDIT_TTL_PRIMARY_S
        } else {
            AUDIT_TTL_FAILOVER_S
        };

        let Some(audit) = lookup_audit(&slot.api_base, &slot.model, &resolved.value) else {
            needs_audit_slots.push((idx, slot));
            continue;
        };

        if !audit.report_age_s.is_finite()
            || audit.report_age_s < 0.0
            || audit.report_age_s > max_ttl
        {
            needs_audit_slots.push((idx, slot));
            continue;
        }

        if audit.safety_stop || audit.verdict_level < 3 {
            return Err(ConfGateError::Validation(format!(
                "Slot {} ({}) blocked by security audit (level {}, safety_stop={})",
                idx, slot.model, audit.verdict_level, audit.safety_stop
            )));
        }

        let permitted = audit.memory_permitted && !audit.safety_stop;
        if idx == 0 && !permitted {
            return Err(ConfGateError::Validation(format!(
                "Primary slot 0 ({}) requires memory_permitted=true in security audit",
                slot.model
            )));
        }
        if idx >= 1 && audit.verdict_level == 3 && !permitted {
            conditional.push(ConditionalSlotWarning {
                slot_index: idx,
                model: slot.model.clone(),
                api_base: slot.api_base.clone(),
                level: audit.verdict_level,
                why: audit.why,
            });
        } else if !permitted {
            return Err(ConfGateError::Validation(format!(
                "Slot {} ({}) is not permitted for memory extraction",
                idx, slot.model
            )));
        }
    }

    if !needs_audit_slots.is_empty() {
        let primary_missing = needs_audit_slots.iter().any(|(idx, _)| *idx == 0);
        if allow_unaudited && !primary_missing {
            for (idx, slot) in needs_audit_slots {
                conditional.push(ConditionalSlotWarning {
                    slot_index: idx,
                    model: slot.model.clone(),
                    api_base: slot.api_base.clone(),
                    level: 0,
                    why: "Saved without fresh security audit via failover override".to_string(),
                });
            }
        } else {
            let slot_indices: Vec<usize> = needs_audit_slots.iter().map(|(i, _)| *i).collect();
            return Err(ConfGateError::AuditRequired {
                message: format!(
                    "Valid security audit report required before saving slot(s): {:?}",
                    slot_indices
                ),
                slots: slot_indices,
            });
        }
    }

    Ok(conditional)
}

/// Applies a single slot edit onto `conf_path` with default live-path protection enabled.
pub fn apply_slot_update<F>(
    conf_path: &Path,
    backups_dir: &Path,
    expected_sha: &str,
    input: &SlotUpdateInput,
    env_map: Option<&HashMap<String, String>>,
    lookup_audit: F,
) -> Result<ApplySlotOutcome, ConfGateError>
where
    F: FnMut(&str, &str, &str) -> Option<CachedAuditVerdict>,
{
    apply_slot_update_with_live_policy(
        conf_path,
        backups_dir,
        expected_sha,
        input,
        env_map,
        None,
        false,
        lookup_audit,
    )
}

/// Applies a single slot edit onto `conf_path` with explicit `allow_live_write` policy for the production desktop host.
#[allow(clippy::too_many_arguments)]
pub fn apply_slot_update_with_live_policy<F>(
    conf_path: &Path,
    backups_dir: &Path,
    expected_sha: &str,
    input: &SlotUpdateInput,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
    allow_live_write: bool,
    lookup_audit: F,
) -> Result<ApplySlotOutcome, ConfGateError>
where
    F: FnMut(&str, &str, &str) -> Option<CachedAuditVerdict>,
{
    let home_var = std::env::var_os("USERPROFILE");
    let home_path = home_var.as_ref().map(Path::new);
    apply_slot_update_internal(
        conf_path,
        backups_dir,
        expected_sha,
        input,
        env_map,
        reports_dir,
        home_path,
        allow_live_write,
        lookup_audit,
    )
}

fn materialize_credentials(
    vlm: &mut VlmConfig,
    existing_effective: &[EffectiveSlot],
) -> Vec<VlmCredentialSlot> {
    match vlm.credentials.take() {
        Some(list) if !list.is_empty() => list,
        _ => existing_effective
            .iter()
            .map(|e| VlmCredentialSlot {
                id: Some(e.id.clone()),
                provider: e.provider.clone(),
                model: Some(e.model.clone()),
                api_base: Some(e.api_base.clone()),
                api_key: Some(e.raw_key.clone()),
                extra: BTreeMap::new(),
            })
            .collect(),
    }
}

fn sync_primary_vlm_fields(vlm: &mut VlmConfig, creds: &[VlmCredentialSlot]) {
    if let Some(first) = creds.first() {
        if let Some(ref model) = first.model {
            vlm.model = model.clone();
        }
        if let Some(ref api_base) = first.api_base {
            vlm.api_base = api_base.clone();
        }
        if let Some(ref api_key) = first.api_key {
            vlm.api_key = api_key.clone();
        }
        if first.provider.is_some() {
            vlm.provider = first.provider.clone();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_vlm_mutation_internal<F, M>(
    conf_path: &Path,
    backups_dir: &Path,
    expected_sha: &str,
    allow_unaudited: bool,
    manual_save: bool,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
    home_dir: Option<&Path>,
    allow_live_write: bool,
    lookup_audit: F,
    mutate: M,
) -> Result<ApplySlotOutcome, ConfGateError>
where
    F: FnMut(&str, &str, &str) -> Option<CachedAuditVerdict>,
    M: FnOnce(&mut OpenVikingConfig, &[EffectiveSlot]) -> Result<(), ConfGateError>,
{
    verify_live_path_for_home(conf_path, home_dir, allow_live_write)?;
    let (before, _, current_sha) = load_raw_config(conf_path)?;
    if current_sha != expected_sha {
        return Err(ConfGateError::RevisionMismatch {
            file: conf_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            expected: expected_sha.to_string(),
            actual: current_sha,
        });
    }

    let existing_effective = extract_effective_slots(&before, env_map);
    let mut after = before.clone();
    mutate(&mut after, &existing_effective)?;

    let warnings = validate_conf_transition(
        &before,
        &after,
        allow_unaudited,
        manual_save,
        env_map,
        lookup_audit,
    )?;

    let (new_sha, backup_path) = save_config_with_backup_for_home(
        conf_path,
        backups_dir,
        &after,
        Some(expected_sha),
        home_dir,
        allow_live_write,
    )?;
    let slots = summarize_slots_with_audits(&after, env_map, reports_dir);

    Ok(ApplySlotOutcome {
        new_sha256: new_sha,
        backup_path: backup_path.as_deref().map(display_clean_path),
        conditional_warnings: warnings,
        slots,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_slot_update_internal<F>(
    conf_path: &Path,
    backups_dir: &Path,
    expected_sha: &str,
    input: &SlotUpdateInput,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
    home_dir: Option<&Path>,
    allow_live_write: bool,
    lookup_audit: F,
) -> Result<ApplySlotOutcome, ConfGateError>
where
    F: FnMut(&str, &str, &str) -> Option<CachedAuditVerdict>,
{
    let clean_model = input.model.trim().to_string();
    let clean_base = validate_endpoint_url(&input.api_base)?;
    commit_vlm_mutation_internal(
        conf_path,
        backups_dir,
        expected_sha,
        input.allow_unaudited,
        input.manual_save,
        env_map,
        reports_dir,
        home_dir,
        allow_live_write,
        lookup_audit,
        move |after, existing_effective| {
            let vlm = after.vlm.as_mut().ok_or_else(|| {
                ConfGateError::Validation("Configuration has no vlm section to update".to_string())
            })?;
            if input.slot_index > existing_effective.len() {
                return Err(ConfGateError::Validation(format!(
                    "Slot index {} is out of range (current count: {})",
                    input.slot_index,
                    existing_effective.len()
                )));
            }
            let mut creds = materialize_credentials(vlm, existing_effective);
            let provided_key = input
                .api_key
                .as_ref()
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty());

            if input.slot_index == creds.len() {
                let new_key = provided_key.ok_or_else(|| {
                    ConfGateError::Validation(
                        "New slot requires a non-empty API key or ${ENV_VAR}".to_string(),
                    )
                })?;
                let new_id = credential_id(&clean_model, &clean_base, &new_key, env_map);
                creds.push(VlmCredentialSlot {
                    id: Some(new_id),
                    provider: input.provider.clone().or_else(|| vlm.provider.clone()),
                    model: Some(clean_model),
                    api_base: Some(clean_base),
                    api_key: Some(new_key),
                    extra: BTreeMap::new(),
                });
            } else {
                let target = &mut creds[input.slot_index];
                let existing_base = target
                    .api_base
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(&vlm.api_base);
                if provided_key.is_none()
                    && normalize_endpoint(&clean_base) != normalize_endpoint(existing_base)
                {
                    return Err(ConfGateError::Validation(
                        "Base URL changed; provide an API key or inherit from matching endpoint"
                            .to_string(),
                    ));
                }
                let effective_key = provided_key
                    .or_else(|| target.api_key.clone())
                    .unwrap_or_else(|| vlm.api_key.clone());
                let new_id = credential_id(&clean_model, &clean_base, &effective_key, env_map);
                target.id = Some(new_id);
                if input.provider.is_some() {
                    target.provider = input.provider.clone();
                }
                target.model = Some(clean_model);
                target.api_base = Some(clean_base);
                target.api_key = Some(effective_key);
                sync_primary_vlm_fields(vlm, &creds);
            }
            vlm.credentials = Some(creds);
            Ok(())
        },
    )
}

/// Reorders two VLM slots (`Swap`) or promotes a fallback slot to Primary `#0` with full audit-gate verification.
#[allow(clippy::too_many_arguments)]
pub fn reorder_slot_with_live_policy<F>(
    conf_path: &Path,
    backups_dir: &Path,
    expected_sha: &str,
    op: &SlotReorderOp,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
    allow_live_write: bool,
    lookup_audit: F,
) -> Result<ApplySlotOutcome, ConfGateError>
where
    F: FnMut(&str, &str, &str) -> Option<CachedAuditVerdict>,
{
    let home_var = std::env::var_os("USERPROFILE");
    let home_path = home_var.as_ref().map(Path::new);
    commit_vlm_mutation_internal(
        conf_path,
        backups_dir,
        expected_sha,
        false,
        false,
        env_map,
        reports_dir,
        home_path,
        allow_live_write,
        lookup_audit,
        move |after, existing_effective| {
            let vlm = after.vlm.as_mut().ok_or_else(|| {
                ConfGateError::Validation("Configuration has no vlm section".to_string())
            })?;
            let mut creds = materialize_credentials(vlm, existing_effective);
            let len = creds.len();
            match *op {
                SlotReorderOp::Swap { a, b } => {
                    if a >= len || b >= len {
                        return Err(ConfGateError::Validation(format!(
                            "Swap indices ({}, {}) out of range (count: {})",
                            a, b, len
                        )));
                    }
                    if a != b {
                        creds.swap(a, b);
                    }
                }
                SlotReorderOp::PromoteToPrimary { index } => {
                    if index >= len {
                        return Err(ConfGateError::Validation(format!(
                            "Slot {} out of range (count: {})",
                            index, len
                        )));
                    }
                    if index > 0 {
                        let chosen = creds.remove(index);
                        creds.insert(0, chosen);
                    }
                }
            }
            sync_primary_vlm_fields(vlm, &creds);
            vlm.credentials = Some(creds);
            Ok(())
        },
    )
}

/// Removes a fallback slot (`slot_index >= 1`), refusing removal of Primary slot `#0`.
#[allow(clippy::too_many_arguments)]
pub fn delete_fallback_slot_with_live_policy<F>(
    conf_path: &Path,
    backups_dir: &Path,
    expected_sha: &str,
    slot_index: usize,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
    allow_live_write: bool,
    lookup_audit: F,
) -> Result<ApplySlotOutcome, ConfGateError>
where
    F: FnMut(&str, &str, &str) -> Option<CachedAuditVerdict>,
{
    let home_var = std::env::var_os("USERPROFILE");
    let home_path = home_var.as_ref().map(Path::new);
    commit_vlm_mutation_internal(
        conf_path,
        backups_dir,
        expected_sha,
        false,
        false,
        env_map,
        reports_dir,
        home_path,
        allow_live_write,
        lookup_audit,
        move |after, existing_effective| {
            if slot_index == 0 {
                return Err(ConfGateError::Validation(
                    "Cannot delete Primary Slot #0; replace or promote another slot instead"
                        .to_string(),
                ));
            }
            let vlm = after.vlm.as_mut().ok_or_else(|| {
                ConfGateError::Validation("Configuration has no vlm section".to_string())
            })?;
            let mut creds = materialize_credentials(vlm, existing_effective);
            if slot_index >= creds.len() {
                return Err(ConfGateError::Validation(format!(
                    "Slot {} out of range (count: {})",
                    slot_index,
                    creds.len()
                )));
            }
            creds.remove(slot_index);
            sync_primary_vlm_fields(vlm, &creds);
            vlm.credentials = Some(creds);
            Ok(())
        },
    )
}

/// Atomically updates `vlm.max_retries`, `failback_timeout_seconds`, and `failback_request_count` in `ov.conf`.
#[allow(clippy::too_many_arguments)]
pub fn update_failback_policy_with_live_policy(
    conf_path: &Path,
    backups_dir: &Path,
    expected_sha: &str,
    max_retries: u32,
    failback_timeout_seconds: u64,
    failback_request_count_ui: u32,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
    live_vlm: Option<&VlmActiveResult>,
    allow_live_write: bool,
) -> Result<ConfigSummary, ConfGateError> {
    if max_retries > 10 {
        return Err(ConfGateError::Validation(
            "max_retries must be between 0 and 10".to_string(),
        ));
    }
    if !(60..=86_400).contains(&failback_timeout_seconds) {
        return Err(ConfGateError::Validation(
            "failback_timeout_seconds must be between 60 and 86400".to_string(),
        ));
    }
    if failback_request_count_ui > 10_000 {
        return Err(ConfGateError::Validation(
            "failback_request_count must be between 0 and 10000".to_string(),
        ));
    }

    let home_var = std::env::var_os("USERPROFILE");
    let home_path = home_var.as_ref().map(Path::new);
    verify_live_path_for_home(conf_path, home_path, allow_live_write)?;
    let (before, _, current_sha) = load_raw_config(conf_path)?;
    if current_sha != expected_sha {
        return Err(ConfGateError::RevisionMismatch {
            file: conf_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            expected: expected_sha.to_string(),
            actual: current_sha,
        });
    }

    let mut after = before.clone();
    let vlm = after
        .vlm
        .as_mut()
        .ok_or_else(|| ConfGateError::Validation("Configuration has no vlm section".to_string()))?;
    vlm.max_retries = Some(max_retries);
    vlm.failback_timeout_seconds = Some(failback_timeout_seconds);
    vlm.failback_request_count = Some(stored_failback_request_count(failback_request_count_ui));

    let (new_sha, _) = save_config_with_backup_for_home(
        conf_path,
        backups_dir,
        &after,
        Some(expected_sha),
        home_path,
        allow_live_write,
    )?;
    Ok(summarize_config_with_audits(
        conf_path,
        &after,
        &new_sha,
        live_vlm,
        env_map,
        reports_dir,
    ))
}

fn verify_live_path_for_home(
    dest_path: &Path,
    home_dir: Option<&Path>,
    allow_live_write: bool,
) -> Result<(), ConfGateError> {
    let allow_live =
        allow_live_write || std::env::var("COCKPIT_ALLOW_LIVE_WRITE").as_deref() == Ok("1");
    if super::safe_write::is_live_path_protected(dest_path, home_dir, allow_live) {
        return Err(ConfGateError::LivePathProtected(
            dest_path.display().to_string(),
        ));
    }
    Ok(())
}

pub fn verify_not_live_path(dest_path: &Path) -> Result<(), ConfGateError> {
    let home_var = std::env::var_os("USERPROFILE");
    let home_path = home_var.as_ref().map(Path::new);
    verify_live_path_for_home(dest_path, home_path, false)
}

pub fn load_raw_config(path: &Path) -> Result<(OpenVikingConfig, String, String), ConfGateError> {
    let raw_text = fs::read_to_string(path)?;
    let sha = sha256_hex(raw_text.as_bytes());
    let clean_json = raw_text.strip_prefix('\u{feff}').unwrap_or(&raw_text);
    let parsed: OpenVikingConfig = serde_json::from_str(clean_json)?;
    Ok((parsed, raw_text, sha))
}

pub fn create_pre_write_backup(
    conf_path: &Path,
    backups_dir: &Path,
) -> Result<PathBuf, ConfGateError> {
    if !conf_path.is_file() {
        return Err(ConfGateError::Validation(format!(
            "Cannot create backup: source file {} does not exist",
            conf_path.display()
        )));
    }

    fs::create_dir_all(backups_dir)?;

    let raw_bytes = fs::read(conf_path)?;
    let sha = sha256_hex(&raw_bytes);
    let hash_prefix = &sha[..8];

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let backup_filename = format!("ov.conf-before-{}Z-{}.bak", now_secs, hash_prefix);
    let backup_path = backups_dir.join(backup_filename);

    write_restricted_bytes_atomic(&backup_path, &raw_bytes)?;

    Ok(backup_path)
}

pub fn save_config_with_backup(
    dest_path: &Path,
    backups_dir: &Path,
    config: &OpenVikingConfig,
    expected_previous_sha: Option<&str>,
) -> Result<(String, Option<PathBuf>), ConfGateError> {
    let home_var = std::env::var_os("USERPROFILE");
    let home_path = home_var.as_ref().map(Path::new);
    save_config_with_backup_for_home(
        dest_path,
        backups_dir,
        config,
        expected_previous_sha,
        home_path,
        false,
    )
}

fn save_config_with_backup_for_home(
    dest_path: &Path,
    backups_dir: &Path,
    config: &OpenVikingConfig,
    expected_previous_sha: Option<&str>,
    home_dir: Option<&Path>,
    allow_live_write: bool,
) -> Result<(String, Option<PathBuf>), ConfGateError> {
    verify_live_path_for_home(dest_path, home_dir, allow_live_write)?;

    if let Some(ref vlm) = config.vlm {
        if vlm.model.trim().is_empty() {
            return Err(ConfGateError::Validation(
                "VLM model cannot be empty".to_string(),
            ));
        }
        if vlm.api_base.trim().is_empty() {
            return Err(ConfGateError::Validation(
                "VLM api_base cannot be empty".to_string(),
            ));
        }
    }

    if let Some(expected_sha) = expected_previous_sha {
        if dest_path.is_file() {
            let current_bytes = fs::read(dest_path)?;
            let current_sha = sha256_hex(&current_bytes);
            if current_sha != expected_sha {
                return Err(ConfGateError::RevisionMismatch {
                    file: dest_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    expected: expected_sha.to_string(),
                    actual: current_sha,
                });
            }
        }
    }

    let backup_path = if dest_path.is_file() {
        Some(create_pre_write_backup(dest_path, backups_dir)?)
    } else {
        None
    };

    let allow_live =
        allow_live_write || std::env::var("COCKPIT_ALLOW_LIVE_WRITE").as_deref() == Ok("1");
    let payload = serde_json::to_string_pretty(config)? + "\n";
    let written_sha = super::safe_write::safe_atomic_write_text_internal(
        dest_path,
        &payload,
        true,
        expected_previous_sha,
        home_dir,
        allow_live,
    )?;

    let (reloaded, _, _) = load_raw_config(dest_path)?;
    if reloaded != *config {
        if let Some(ref bak) = backup_path {
            if let Ok(bak_bytes) = fs::read(bak) {
                let _ = super::safe_write::safe_atomic_write_text_internal(
                    dest_path,
                    &String::from_utf8_lossy(&bak_bytes),
                    true,
                    None,
                    home_dir,
                    allow_live,
                );
            }
        }
        return Err(ConfGateError::Validation(
            "Post-write verification failed: reloaded configuration does not match source struct"
                .to_string(),
        ));
    }

    Ok((written_sha, backup_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_and_save_without_env_expansion() {
        let dir = tempdir().expect("create tempdir");
        let conf_path = dir.path().join("ov.conf");
        let backups_dir = dir.path().join("backups");

        let initial_json = r#"{
  "vlm": {
    "model": "qwen2.5-vl-7b-instruct",
    "api_base": "https://api.example.com/v1",
    "api_key": "${MY_SECRET_KEY_VAR}",
    "thinking": true
  },
  "embedding": {
    "dense": {
      "model": "qwen3-embedding:0.6b"
    }
  }
}
"#;
        fs::write(&conf_path, initial_json).expect("write initial ov.conf");

        let (mut cfg, _, sha1) = load_raw_config(&conf_path).expect("load config");
        assert_eq!(
            cfg.vlm.as_ref().unwrap().api_key,
            "${MY_SECRET_KEY_VAR}",
            "Environment variable placeholder was corrupted or expanded!"
        );

        cfg.vlm.as_mut().unwrap().model = "qwen2.5-vl-72b-instruct".to_string();

        let (sha2, backup_path) =
            save_config_with_backup(&conf_path, &backups_dir, &cfg, Some(&sha1))
                .expect("save config");

        assert_ne!(sha1, sha2);
        assert!(backup_path.is_some());
        assert!(backup_path.unwrap().is_file());

        let (reloaded, reloaded_text, _) = load_raw_config(&conf_path).expect("reload config");
        assert_eq!(
            reloaded.vlm.as_ref().unwrap().api_key,
            "${MY_SECRET_KEY_VAR}",
            "Write-back leaked or altered variable syntax!"
        );
        assert!(reloaded_text.contains("\"${MY_SECRET_KEY_VAR}\""));
    }

    #[test]
    fn test_save_empty_model_fails_closed() {
        let dir = tempdir().expect("create tempdir");
        let conf_path = dir.path().join("ov.conf");
        let backups_dir = dir.path().join("backups");

        let bad_cfg = OpenVikingConfig {
            vlm: Some(VlmConfig {
                provider: None,
                model: "   ".to_string(),
                api_base: "https://api.example.com".to_string(),
                api_key: "key".to_string(),
                thinking: None,
                max_retries: None,
                failback_timeout_seconds: None,
                failback_request_count: None,
                credentials: None,
                extra: Default::default(),
            }),
            embedding: None,
            extra: Default::default(),
        };

        let res = save_config_with_backup(&conf_path, &backups_dir, &bad_cfg, None);
        assert!(matches!(res, Err(ConfGateError::Validation(_))));
        assert!(!conf_path.exists());
    }

    #[test]
    fn test_load_and_save_with_utf8_bom() {
        let dir = tempdir().expect("create tempdir");
        let conf_path = dir.path().join("ov.conf");
        let backups_dir = dir.path().join("backups");

        let bom_json = "\u{feff}{\n  \"vlm\": {\n    \"model\": \"qwen2.5-vl-7b-instruct\",\n    \"api_base\": \"https://api.example.com/v1\",\n    \"api_key\": \"${MY_KEY}\"\n  }\n}\n";
        fs::write(&conf_path, bom_json.as_bytes()).expect("write bom ov.conf");

        let (cfg, raw, sha1) = load_raw_config(&conf_path).expect("load bom config");
        assert_eq!(cfg.vlm.as_ref().unwrap().model, "qwen2.5-vl-7b-instruct");
        assert_eq!(sha1, sha256_hex(bom_json.as_bytes()));
        assert!(raw.starts_with('\u{feff}'));

        let (sha2, backup_path) =
            save_config_with_backup(&conf_path, &backups_dir, &cfg, Some(&sha1))
                .expect("save config with bom backup");

        assert_ne!(sha1, sha2);
        let backup = backup_path.expect("backup created");
        let backup_bytes = fs::read(backup).expect("read backup");
        assert_eq!(sha256_hex(&backup_bytes), sha1);
        assert!(backup_bytes.starts_with(&[0xef, 0xbb, 0xbf]));

        let (reloaded, reloaded_text, sha_reloaded) =
            load_raw_config(&conf_path).expect("reload config");
        assert_eq!(sha_reloaded, sha2);
        assert!(!reloaded_text.starts_with('\u{feff}'));
        assert_eq!(reloaded.vlm.as_ref().unwrap().api_key, "${MY_KEY}");
    }

    #[test]
    fn test_slot_gatekeeper_primary_vs_failover_and_redaction() {
        let dir = tempdir().expect("create tempdir");
        let conf_path = dir.path().join("ov.conf");
        let backups_dir = dir.path().join("backups");

        let mut env = HashMap::new();
        env.insert(
            "SLOT0_KEY".to_string(),
            "SYNTHETIC_PRIMARY_KEY_001".to_string(),
        );
        env.insert(
            "SLOT1_KEY".to_string(),
            "SYNTHETIC_FALLBACK_KEY_002".to_string(),
        );

        let initial_json = r#"{
  "vlm": {
    "provider": "openai",
    "model": "primary-v1",
    "api_base": "https://api.example.com/v1",
    "api_key": "${SLOT0_KEY}",
    "failback_timeout_seconds": 3600,
    "credentials": [
      {
        "id": "cred-primary",
        "provider": "openai",
        "model": "primary-v1",
        "api_base": "https://api.example.com/v1",
        "api_key": "${SLOT0_KEY}"
      },
      {
        "id": "cred-fallback",
        "provider": "openai",
        "model": "fallback-v1",
        "api_base": "https://backup.example.com/v1",
        "api_key": "${SLOT1_KEY}"
      }
    ]
  },
  "embedding": {
    "dense": {
      "provider": "ollama",
      "model": "qwen3-embedding:0.6b",
      "api_base": "http://127.0.0.1:21434/v1",
      "dimension": 1024
    }
  }
}
"#;
        fs::write(&conf_path, initial_json).expect("write multi-slot ov.conf");

        let (cfg, _, sha1) = load_raw_config(&conf_path).expect("load multi-slot");
        let summary = summarize_config(&conf_path, &cfg, &sha1, None, Some(&env));
        let serialized_summary = serde_json::to_string(&summary).expect("serialize summary");
        assert!(!serialized_summary.contains("SYNTHETIC_PRIMARY_KEY_001"));
        assert!(!serialized_summary.contains("${SLOT0_KEY}"));
        assert_eq!(summary.slots.len(), 2);
        assert_eq!(
            summary.embedding_model.as_deref(),
            Some("qwen3-embedding:0.6b")
        );

        // 1. Primary slot 0 cannot bypass audit via allow_unaudited=true
        let blocked_primary = apply_slot_update(
            &conf_path,
            &backups_dir,
            &sha1,
            &SlotUpdateInput {
                slot_index: 0,
                provider: Some("openai".to_string()),
                model: "unaudited-primary-v2".to_string(),
                api_base: "https://api.example.com/v1".to_string(),
                api_key: None,
                allow_unaudited: true,
                manual_save: false,
            },
            Some(&env),
            |_, _, _| None,
        );
        assert!(matches!(
            blocked_primary,
            Err(ConfGateError::AuditRequired { .. })
        ));

        // 2. Failover slot 1 succeeds with allow_unaudited=true and returns a conditional warning
        let failover_ok = apply_slot_update(
            &conf_path,
            &backups_dir,
            &sha1,
            &SlotUpdateInput {
                slot_index: 1,
                provider: Some("openai".to_string()),
                model: "unaudited-fallback-v2".to_string(),
                api_base: "https://backup.example.com/v1".to_string(),
                api_key: None,
                allow_unaudited: true,
                manual_save: false,
            },
            Some(&env),
            |_, _, _| None,
        )
        .expect("allow_unaudited failover save");
        assert_eq!(failover_ok.conditional_warnings.len(), 1);
        assert_eq!(failover_ok.slots[1].model, "unaudited-fallback-v2");

        // 3. Primary slot 0 succeeds when fresh Level 5 audit report permits memory
        let primary_ok = apply_slot_update(
            &conf_path,
            &backups_dir,
            &failover_ok.new_sha256,
            &SlotUpdateInput {
                slot_index: 0,
                provider: Some("openai".to_string()),
                model: "audited-primary-v2".to_string(),
                api_base: "https://api.example.com/v1".to_string(),
                api_key: None,
                allow_unaudited: false,
                manual_save: false,
            },
            Some(&env),
            |_, model, _| {
                if model == "audited-primary-v2" {
                    Some(CachedAuditVerdict {
                        report_age_s: 120.0,
                        verdict_level: 5,
                        memory_permitted: true,
                        safety_stop: false,
                        why: String::new(),
                    })
                } else {
                    None
                }
            },
        )
        .expect("audited primary save");
        assert!(primary_ok.conditional_warnings.is_empty());
        assert_eq!(primary_ok.slots[0].model, "audited-primary-v2");

        // 4. Fake home `.openviking/ov.conf` blocks un-authorized writes, permits authorized desktop saves
        let fake_home = dir.path().join("fake_user_home");
        let fake_ov = fake_home.join(".openviking");
        let fake_conf = fake_ov.join("ov.conf");
        let fake_backups = fake_ov.join("backups");
        fs::create_dir_all(&fake_ov).expect("create fake_ov");
        fs::write(&fake_conf, initial_json).expect("write fake live ov.conf");
        let (_, _, fake_sha) = load_raw_config(&fake_conf).expect("load fake live ov.conf");

        let blocked_live = apply_slot_update_internal(
            &fake_conf,
            &fake_backups,
            &fake_sha,
            &SlotUpdateInput {
                slot_index: 1,
                provider: Some("openai".to_string()),
                model: "blocked-live-edit".to_string(),
                api_base: "https://backup.example.com/v1".to_string(),
                api_key: None,
                allow_unaudited: true,
                manual_save: false,
            },
            Some(&env),
            None,
            Some(&fake_home),
            false,
            |_, _, _| None,
        );
        assert!(matches!(
            blocked_live,
            Err(ConfGateError::LivePathProtected(_))
        ));

        let authorized_live = apply_slot_update_internal(
            &fake_conf,
            &fake_backups,
            &fake_sha,
            &SlotUpdateInput {
                slot_index: 1,
                provider: Some("openai".to_string()),
                model: "authorized-gui-edit".to_string(),
                api_base: "https://backup.example.com/v1".to_string(),
                api_key: None,
                allow_unaudited: true,
                manual_save: false,
            },
            Some(&env),
            None,
            Some(&fake_home),
            true,
            |_, _, _| None,
        )
        .expect("authorized desktop slot save on fake home");
        assert_eq!(authorized_live.slots[1].model, "authorized-gui-edit");
        assert!(authorized_live.backup_path.is_some());
    }

    #[test]
    fn test_resolve_server_root_api_key_resolves_literal_and_env_ref() {
        let mut env = HashMap::new();
        env.insert(
            "OV_ROOT_SECRET".to_string(),
            "SYNTHETIC_ROOT_API_KEY_555".to_string(),
        );

        let env_cfg: OpenVikingConfig =
            serde_json::from_str(r#"{"server":{"port":19330,"root_api_key":"${OV_ROOT_SECRET}"}}"#)
                .expect("parse env root_api_key");
        assert_eq!(
            resolve_server_root_api_key(&env_cfg, Some(&env)).as_deref(),
            Some("SYNTHETIC_ROOT_API_KEY_555")
        );
        assert_eq!(
            resolve_server_root_api_key(&env_cfg, Some(&HashMap::new())),
            None
        );

        let lit_cfg: OpenVikingConfig =
            serde_json::from_str(r#"{"server":{"root_api_key":"  literal-root-token  "}}"#)
                .expect("parse literal root_api_key");
        assert_eq!(
            resolve_server_root_api_key(&lit_cfg, None).as_deref(),
            Some("literal-root-token")
        );

        let dpapi_cfg: OpenVikingConfig =
            serde_json::from_str(r#"{"server":{"root_api_key":"dpapi:AAA"}}"#)
                .expect("parse dpapi root_api_key");
        assert_eq!(resolve_server_root_api_key(&dpapi_cfg, None), None);
    }

    #[test]
    fn test_slot_reorder_delete_failback_and_cross_endpoint_rejection() {
        let dir = tempdir().expect("tempdir");
        let conf_path = dir.path().join("ov.conf");
        let backups_dir = dir.path().join("backups");

        let mut env = HashMap::new();
        env.insert("K0".to_string(), "SYNTHETIC_S0".to_string());
        env.insert("K1".to_string(), "SYNTHETIC_S1".to_string());
        env.insert("K2".to_string(), "SYNTHETIC_S2".to_string());

        let initial_json = r#"{
  "vlm": {
    "provider": "openai",
    "model": "m0",
    "api_base": "https://a.example.com/v1",
    "api_key": "${K0}",
    "credentials": [
      {"id": "c0", "provider": "openai", "model": "m0", "api_base": "https://a.example.com/v1", "api_key": "${K0}"},
      {"id": "c1", "provider": "openai", "model": "m1", "api_base": "https://b.example.com/v1", "api_key": "${K1}"},
      {"id": "c2", "provider": "openai", "model": "m2", "api_base": "https://c.example.com/v1", "api_key": "${K2}"}
    ]
  }
}"#;
        fs::write(&conf_path, initial_json).expect("write initial ov.conf");
        let (_, _, sha1) = load_raw_config(&conf_path).expect("load initial");

        // Changing base URL on existing slot without key must fail closed
        let cross_ep = apply_slot_update(
            &conf_path,
            &backups_dir,
            &sha1,
            &SlotUpdateInput {
                slot_index: 1,
                provider: None,
                model: "m1".to_string(),
                api_base: "https://evil.example.com/v1".to_string(),
                api_key: None,
                allow_unaudited: true,
                manual_save: false,
            },
            Some(&env),
            |_, _, _| None,
        );
        assert!(matches!(cross_ep, Err(ConfGateError::Validation(_))));

        // Swap fallback slots 1 <-> 2 works cleanly
        let swapped = reorder_slot_with_live_policy(
            &conf_path,
            &backups_dir,
            &sha1,
            &SlotReorderOp::Swap { a: 1, b: 2 },
            Some(&env),
            None,
            false,
            |_, _, _| None,
        )
        .expect("swap fallback slots 1 <-> 2");
        assert_eq!(swapped.slots[1].model, "m2");
        assert_eq!(swapped.slots[2].model, "m1");

        // Promote to primary fails without fresh audit
        let blocked_promote = reorder_slot_with_live_policy(
            &conf_path,
            &backups_dir,
            &swapped.new_sha256,
            &SlotReorderOp::PromoteToPrimary { index: 1 },
            Some(&env),
            None,
            false,
            |_, _, _| None,
        );
        assert!(matches!(
            blocked_promote,
            Err(ConfGateError::AuditRequired { .. })
        ));

        // Promote succeeds when M5 fresh audit is present and syncs top-level vlm.*
        let promoted = reorder_slot_with_live_policy(
            &conf_path,
            &backups_dir,
            &swapped.new_sha256,
            &SlotReorderOp::PromoteToPrimary { index: 1 },
            Some(&env),
            None,
            false,
            |_, model, _| {
                if model == "m2" {
                    Some(CachedAuditVerdict {
                        report_age_s: 30.0,
                        verdict_level: 5,
                        memory_permitted: true,
                        safety_stop: false,
                        why: String::new(),
                    })
                } else {
                    None
                }
            },
        )
        .expect("promote m2 to primary");
        assert_eq!(promoted.slots[0].model, "m2");
        let (reloaded_cfg, _, _) = load_raw_config(&conf_path).unwrap();
        assert_eq!(reloaded_cfg.vlm.as_ref().unwrap().model, "m2");

        // Deleting Primary #0 must be rejected; deleting #2 succeeds
        assert!(delete_fallback_slot_with_live_policy(
            &conf_path,
            &backups_dir,
            &promoted.new_sha256,
            0,
            Some(&env),
            None,
            false,
            |_, _, _| None,
        )
        .is_err());

        let deleted = delete_fallback_slot_with_live_policy(
            &conf_path,
            &backups_dir,
            &promoted.new_sha256,
            2,
            Some(&env),
            None,
            false,
            |_, _, _| None,
        )
        .expect("delete fallback slot 2");
        assert_eq!(deleted.slots.len(), 2);

        // Failback policy 0 <-> INT32_MAX roundtrip
        let pol = update_failback_policy_with_live_policy(
            &conf_path,
            &backups_dir,
            &deleted.new_sha256,
            4,
            1800,
            0,
            Some(&env),
            None,
            None,
            false,
        )
        .expect("update failback policy");
        assert_eq!(pol.max_retries, Some(4));
        assert_eq!(pol.failback_timeout_seconds, Some(1800));
        assert_eq!(pol.failback_request_count, 0);
        let (cfg_after_pol, _, _) = load_raw_config(&conf_path).unwrap();
        assert_eq!(
            cfg_after_pol.vlm.as_ref().unwrap().failback_request_count,
            Some(FAILBACK_REQUEST_COUNT_UNLIMITED)
        );
    }
}
