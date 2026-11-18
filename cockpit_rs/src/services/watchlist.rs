//! Bounded credential watchlist (`MAX_WATCHES = 4`), DPAPI reserve pool state (`monitor.json`),
//! and sequential probe worker with consecutive 401/403 auto-disable policy.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::conf_gate::AUDIT_TTL_FAILOVER_S;
use crate::config::safe_write::{
    apply_restricted_file_acl, safe_atomic_write_text_with_live_policy, sha256_hex, SafeWriteError,
};
use crate::secrets::secret_store::{dpapi_protect, resolve_secret, SecretStatus};
use crate::services::auditor_cache::load_cached_audit_verdict;

pub const MAX_WATCHES: usize = 4;
pub const LEGACY_MAX_WATCHES: usize = 7;
pub const MAX_MONITOR_STATE_BACKUPS: usize = 30;
pub const WATCH_PROBE_TIMEOUT_MS: u64 = 20_000;
pub const WATCH_MAX_TOKENS: u32 = 64;
pub const BACKOFF_CAP_SECS: f64 = 3_600.0;
pub const MIN_WINDOW_WIDTH: u32 = 880;
pub const MIN_WINDOW_HEIGHT: u32 = 560;
pub const MAX_WINDOW_WIDTH: u32 = 3840;
pub const MAX_WINDOW_HEIGHT: u32 = 2160;
const WINDOW_POS_BOUND: i32 = 16_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowGeometry {
    pub width: u32,
    pub height: u32,
    pub x: Option<i32>,
    pub y: Option<i32>,
}

fn parse_signed_offset(input: &str) -> Option<(i32, &str)> {
    let s = input.strip_prefix('+').unwrap_or(input);
    let (neg, digits_src) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };
    let digit_len = digits_src
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digit_len == 0 {
        return None;
    }
    let mag: i32 = digits_src[..digit_len].parse().ok()?;
    let val = if neg { -mag } else { mag };
    Some((val, &digits_src[digit_len..]))
}

pub fn parse_window_geometry(raw: &str) -> Option<WindowGeometry> {
    let trimmed = raw.trim();
    let x_idx = trimmed.find(['x', 'X'])?;
    let raw_w: u32 = trimmed[..x_idx].parse().ok()?;
    let after_x = &trimmed[x_idx + 1..];
    let h_len = after_x.bytes().take_while(|b| b.is_ascii_digit()).count();
    if h_len == 0 {
        return None;
    }
    let raw_h: u32 = after_x[..h_len].parse().ok()?;
    if raw_w < 200 || raw_h < 200 {
        return None;
    }
    let width = raw_w.clamp(MIN_WINDOW_WIDTH, MAX_WINDOW_WIDTH);
    let height = raw_h.clamp(MIN_WINDOW_HEIGHT, MAX_WINDOW_HEIGHT);
    let rest = &after_x[h_len..];
    if rest.is_empty() {
        return Some(WindowGeometry {
            width,
            height,
            x: None,
            y: None,
        });
    }
    if !rest.starts_with(['+', '-']) {
        return None;
    }
    let (px, rem) = parse_signed_offset(rest)?;
    if !rem.starts_with(['+', '-']) {
        return None;
    }
    let (py, tail) = parse_signed_offset(rem)?;
    if !tail.is_empty() {
        return None;
    }
    if px.abs() >= WINDOW_POS_BOUND || py.abs() >= WINDOW_POS_BOUND {
        return Some(WindowGeometry {
            width,
            height,
            x: None,
            y: None,
        });
    }
    Some(WindowGeometry {
        width,
        height,
        x: Some(px),
        y: Some(py),
    })
}

pub fn format_window_geometry(
    width: u32,
    height: u32,
    x: Option<i32>,
    y: Option<i32>,
) -> Option<String> {
    if width < 200 || height < 200 {
        return None;
    }
    let w = width.clamp(MIN_WINDOW_WIDTH, MAX_WINDOW_WIDTH);
    let h = height.clamp(MIN_WINDOW_HEIGHT, MAX_WINDOW_HEIGHT);
    match (x, y) {
        (Some(px), Some(py)) => {
            if px.abs() >= WINDOW_POS_BOUND || py.abs() >= WINDOW_POS_BOUND {
                return None;
            }
            let fmt_coord = |v: i32| {
                if v >= 0 {
                    format!("+{}", v)
                } else {
                    format!("+-{}", -(v as i64))
                }
            };
            Some(format!("{}x{}{}{}", w, h, fmt_coord(px), fmt_coord(py)))
        }
        _ => Some(format!("{}x{}", w, h)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("Safe write error: {0}")]
    SafeWrite(#[from] SafeWriteError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Corrupted or unreadable monitor state: {0}")]
    CorruptedState(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("State revision conflict: expected {expected}, found {actual}")]
    RevisionConflict { expected: String, actual: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeOutcome {
    pub ok: bool,
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
    pub at: f64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchRecord {
    pub id: String,
    #[serde(default)]
    pub alias: String,
    pub model: String,
    pub api_base: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub auto_enabled: bool,
    #[serde(default)]
    pub auto_disabled_reason: String,
    #[serde(default)]
    pub rev: u64,
    #[serde(default)]
    pub fail_streak: u32,
    #[serde(default)]
    pub auth_fail_streak: u32,
    #[serde(default)]
    pub next_probe_at: f64,
    #[serde(default)]
    pub cooldown_until: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probe: Option<ProbeOutcome>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl fmt::Debug for WatchRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchRecord")
            .field("id", &self.id)
            .field("alias", &self.alias)
            .field("model", &self.model)
            .field("api_base", &self.api_base)
            .field("api_key", &"[REDACTED]")
            .field("auto_enabled", &self.auto_enabled)
            .field("rev", &self.rev)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SpareModelRecord {
    pub model: String,
    pub api_base: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub note: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl fmt::Debug for SpareModelRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpareModelRecord")
            .field("model", &self.model)
            .field("api_base", &self.api_base)
            .field("api_key", &"[REDACTED]")
            .field("note", &self.note)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorState {
    #[serde(default)]
    pub run_with_windows: bool,
    #[serde(default = "default_true")]
    pub notify_on_down: bool,
    #[serde(default = "default_true")]
    pub notify_on_failover: bool,
    #[serde(default)]
    pub always_on_top: bool,
    #[serde(default = "default_geometry")]
    pub geometry: String,
    #[serde(default)]
    pub watch_auto_enabled: bool,
    #[serde(
        rename = "watch_auto_minutes",
        alias = "watch_interval_minutes",
        default = "default_watch_minutes"
    )]
    pub watch_interval_minutes: u32,
    #[serde(default)]
    pub watch_keys: Vec<WatchRecord>,
    #[serde(default)]
    pub spare_models: Vec<SpareModelRecord>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Default for MonitorState {
    fn default() -> Self {
        Self {
            run_with_windows: false,
            notify_on_down: default_true(),
            notify_on_failover: default_true(),
            always_on_top: false,
            geometry: default_geometry(),
            watch_auto_enabled: false,
            watch_interval_minutes: default_watch_minutes(),
            watch_keys: Vec::new(),
            spare_models: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_geometry() -> String {
    "1020x640".to_string()
}

fn default_watch_minutes() -> u32 {
    10
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchRowView {
    pub id: String,
    pub alias: String,
    pub model: String,
    pub api_base: String,
    pub secret_status: SecretStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_audit_level: Option<u8>,
    pub auto_enabled: bool,
    pub auto_disabled_reason: String,
    pub rev: u64,
    pub fail_streak: u32,
    pub auth_fail_streak: u32,
    pub last_probe: Option<ProbeOutcome>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReserveRowView {
    pub index: usize,
    pub model: String,
    pub api_base: String,
    pub note: String,
    pub secret_status: SecretStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_audit_level: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorStateSummary {
    pub sha256: String,
    pub reserves_sha256: String,
    #[serde(default)]
    pub run_with_windows: bool,
    pub notify_on_down: bool,
    pub notify_on_failover: bool,
    pub watch_auto_enabled: bool,
    pub watch_interval_minutes: u32,
    pub watches: Vec<WatchRowView>,
    pub reserves: Vec<ReserveRowView>,
}

pub fn compute_reserves_sha256(spares: &[SpareModelRecord]) -> String {
    let bytes = serde_json::to_vec(spares).unwrap_or_default();
    sha256_hex(&bytes)
}

pub fn verify_reserves_sha(
    spares: &[SpareModelRecord],
    expected_reserves_sha: &str,
) -> Result<(), WatchError> {
    let actual = compute_reserves_sha256(spares);
    if actual != expected_reserves_sha {
        return Err(WatchError::RevisionConflict {
            expected: expected_reserves_sha.to_string(),
            actual,
        });
    }
    Ok(())
}

#[derive(Clone, Deserialize)]
pub struct UpsertWatchInput {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub alias: String,
    pub model: String,
    pub api_base: String,
    #[serde(default)]
    pub api_key: Option<String>,
}

impl fmt::Debug for UpsertWatchInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpsertWatchInput")
            .field("id", &self.id)
            .field("alias", &self.alias)
            .field("model", &self.model)
            .field("api_base", &self.api_base)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Emitted when two consecutive HTTP 401/403 responses auto-disable a watch credential (`COCKPIT_RUST_SPEC` §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoDisabledAlert {
    pub watch_id: String,
    pub alias: String,
    pub model: String,
    pub status_code: u16,
}

pub fn validate_watch_base_url(raw: &str) -> Result<String, WatchError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 || trimmed.chars().any(|c| c <= ' ') {
        return Err(WatchError::Validation("Invalid Watch Base URL".to_string()));
    }
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|_| WatchError::Validation("Invalid Watch Base URL".to_string()))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(WatchError::Validation(
            "Watch Base URL must use http or https".to_string(),
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(WatchError::Validation(
            "Watch Base URL must not embed credentials, query, or fragment".to_string(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| WatchError::Validation("Missing hostname in Watch Base URL".to_string()))?;
    let is_local = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if scheme == "http" && !is_local {
        return Err(WatchError::Validation(
            "Remote Watch endpoints must use HTTPS".to_string(),
        ));
    }
    let clean_path = parsed.path().trim_end_matches('/');
    if !clean_path.ends_with("/v1") {
        return Err(WatchError::Validation(
            "Watch Base URL must end with /v1".to_string(),
        ));
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

pub fn validate_watch_records_with_cap(
    items: &[WatchRecord],
    cap: usize,
) -> Result<(), WatchError> {
    if items.len() > cap {
        return Err(WatchError::Validation(format!(
            "Watchlist exceeds maximum capacity of {}",
            cap
        )));
    }
    let mut seen = HashSet::new();
    for item in items {
        if item.id.trim().is_empty() || !seen.insert(item.id.clone()) {
            return Err(WatchError::Validation(
                "Invalid or duplicate watch record ID".to_string(),
            ));
        }
        if !item.next_probe_at.is_finite()
            || item.next_probe_at < 0.0
            || !item.cooldown_until.is_finite()
            || item.cooldown_until < 0.0
        {
            return Err(WatchError::Validation(
                "Watch timestamps must be finite and non-negative".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_watch_records(items: &[WatchRecord]) -> Result<(), WatchError> {
    validate_watch_records_with_cap(items, MAX_WATCHES)
}

/// Loads `monitor.json` fail-closed: damaged existing files error instead of silently resetting to empty defaults.
pub fn load_monitor_state(path: &Path) -> Result<(MonitorState, String), WatchError> {
    if !path.exists() {
        return Ok((MonitorState::default(), "<absent>".to_string()));
    }
    let raw_bytes = fs::read(path)?;
    let sha = sha256_hex(&raw_bytes);
    let text = std::str::from_utf8(&raw_bytes)
        .map_err(|_| WatchError::CorruptedState("monitor.json is not valid UTF-8".to_string()))?;
    let clean = text.strip_prefix('\u{feff}').unwrap_or(text);
    let val: Value = serde_json::from_str(clean)
        .map_err(|_| WatchError::CorruptedState("monitor.json failed JSON parse".to_string()))?;
    if !val.is_object() {
        return Err(WatchError::CorruptedState(
            "monitor.json root must be a JSON object".to_string(),
        ));
    }
    let mut state: MonitorState = serde_json::from_value(val)
        .map_err(|_| WatchError::CorruptedState("monitor.json schema mismatch".to_string()))?;
    state.extra.remove("watch_interval_minutes");
    validate_watch_records_with_cap(&state.watch_keys, LEGACY_MAX_WATCHES)?;
    Ok((state, sha))
}

pub fn save_monitor_state(
    path: &Path,
    backups_dir: &Path,
    state: &MonitorState,
    expected_sha: &str,
) -> Result<String, WatchError> {
    save_monitor_state_with_live_policy(path, backups_dir, state, expected_sha, false)
}

pub fn save_monitor_state_with_live_policy(
    path: &Path,
    backups_dir: &Path,
    state: &MonitorState,
    expected_sha: &str,
    allow_live_write: bool,
) -> Result<String, WatchError> {
    let mut effective_cap = MAX_WATCHES;
    if path.exists() {
        if let Ok((existing, _)) = load_monitor_state(path) {
            if state.watch_keys.len() <= existing.watch_keys.len() {
                effective_cap = existing
                    .watch_keys
                    .len()
                    .clamp(MAX_WATCHES, LEGACY_MAX_WATCHES);
            }
        }
    }
    validate_watch_records_with_cap(&state.watch_keys, effective_cap)?;

    let prev_sha = if path.exists() {
        let cur = sha256_hex(&fs::read(path)?);
        if cur != expected_sha {
            return Err(WatchError::RevisionConflict {
                expected: expected_sha.to_string(),
                actual: cur,
            });
        }
        let state_row_root = backups_dir.join("monitor-state");
        let state_bak_dir = state_row_root.join(&cur);
        if !state_bak_dir.exists() {
            fs::create_dir_all(&state_bak_dir)?;
            let bak_file = state_bak_dir.join("monitor.json");
            fs::copy(path, &bak_file)?;
            apply_restricted_file_acl(&bak_file)?;
        }
        prune_monitor_state_backups(&state_row_root, MAX_MONITOR_STATE_BACKUPS);
        Some(expected_sha)
    } else if expected_sha != "<absent>" {
        return Err(WatchError::RevisionConflict {
            expected: expected_sha.to_string(),
            actual: "<absent>".to_string(),
        });
    } else {
        None
    };

    let mut clean_state = state.clone();
    clean_state.extra.remove("watch_interval_minutes");
    let payload = serde_json::to_string_pretty(&clean_state)
        .map_err(|e| WatchError::CorruptedState(e.to_string()))?
        + "\n";
    let new_sha =
        safe_atomic_write_text_with_live_policy(path, &payload, true, prev_sha, allow_live_write)?;
    Ok(new_sha)
}

/// Keeps at most `keep` newest `<64-hex-sha>` subdirectories under `backups/monitor-state/`.
pub fn prune_monitor_state_backups(state_root: &Path, keep: usize) {
    let Ok(rd) = fs::read_dir(state_root) else {
        return;
    };
    let mut dirs: Vec<(SystemTime, std::path::PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let ft = e.file_type().ok()?;
            if !ft.is_dir() || ft.is_symlink() {
                return None;
            }
            let name = e.file_name();
            let s = name.to_str()?;
            if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let mtime = e.metadata().ok()?.modified().ok()?;
            Some((mtime, e.path()))
        })
        .collect();
    dirs.sort_by_key(|b| std::cmp::Reverse(b.0));
    for (_, old_path) in dirs.into_iter().skip(keep) {
        let _ = fs::remove_dir_all(old_path);
    }
}

pub fn summarize_monitor_state(
    state: &MonitorState,
    sha256: &str,
    env_map: Option<&HashMap<String, String>>,
) -> MonitorStateSummary {
    summarize_monitor_state_with_audits(state, sha256, env_map, None)
}

pub fn summarize_monitor_state_with_audits(
    state: &MonitorState,
    sha256: &str,
    env_map: Option<&HashMap<String, String>>,
    reports_dir: Option<&Path>,
) -> MonitorStateSummary {
    let watches = state
        .watch_keys
        .iter()
        .map(|w| {
            let resolved = resolve_secret(&w.api_key, env_map);
            let cached_audit_level = match (reports_dir, resolved.status) {
                (Some(dir), SecretStatus::SecretReady) => load_cached_audit_verdict(
                    dir,
                    &w.api_base,
                    &w.model,
                    &resolved.value,
                    AUDIT_TTL_FAILOVER_S,
                )
                .map(|v| v.verdict_level),
                _ => None,
            };
            WatchRowView {
                id: w.id.clone(),
                alias: w.alias.clone(),
                model: w.model.clone(),
                api_base: w.api_base.clone(),
                secret_status: resolved.status,
                cached_audit_level,
                auto_enabled: w.auto_enabled,
                auto_disabled_reason: w.auto_disabled_reason.clone(),
                rev: w.rev,
                fail_streak: w.fail_streak,
                auth_fail_streak: w.auth_fail_streak,
                last_probe: w.last_probe.clone(),
            }
        })
        .collect();

    let reserves = state
        .spare_models
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            let resolved = resolve_secret(&r.api_key, env_map);
            let cached_audit_level = match (reports_dir, resolved.status) {
                (Some(dir), SecretStatus::SecretReady) => load_cached_audit_verdict(
                    dir,
                    &r.api_base,
                    &r.model,
                    &resolved.value,
                    AUDIT_TTL_FAILOVER_S,
                )
                .map(|v| v.verdict_level),
                _ => None,
            };
            ReserveRowView {
                index: idx,
                model: r.model.clone(),
                api_base: r.api_base.clone(),
                note: r.note.clone(),
                secret_status: resolved.status,
                cached_audit_level,
            }
        })
        .collect();

    MonitorStateSummary {
        sha256: sha256.to_string(),
        reserves_sha256: compute_reserves_sha256(&state.spare_models),
        run_with_windows: state.run_with_windows,
        notify_on_down: state.notify_on_down,
        notify_on_failover: state.notify_on_failover,
        watch_auto_enabled: state.watch_auto_enabled,
        watch_interval_minutes: state.watch_interval_minutes,
        watches,
        reserves,
    }
}

fn encrypt_for_monitor_storage(raw_input: &str) -> Result<String, WatchError> {
    let trimmed = raw_input.trim();
    if trimmed.starts_with("dpapi:") {
        return Err(WatchError::Validation(
            "Do not enter raw dpapi: strings; provide plaintext key or ${ENV_VAR}".to_string(),
        ));
    }
    if crate::secrets::secret_store::is_env_ref(trimmed) {
        return Ok(trimmed.to_string());
    }
    #[cfg(windows)]
    {
        dpapi_protect(trimmed, Some("OpenViking DPAPI"))
            .map_err(|e| WatchError::Validation(format!("DPAPI protection failed: {}", e)))
    }
    #[cfg(not(windows))]
    {
        Ok(trimmed.to_string())
    }
}

pub fn upsert_watch_record(
    state: &mut MonitorState,
    input: &UpsertWatchInput,
) -> Result<String, WatchError> {
    let alias = input.alias.trim().to_string();
    let model = input.model.trim().to_string();
    if model.is_empty() {
        return Err(WatchError::Validation(
            "Watch model cannot be empty".to_string(),
        ));
    }
    for s in [&alias, &model] {
        if s.len() > 2048 || s.chars().any(|c| (c as u32) < 32 || (c as u32) == 127) {
            return Err(WatchError::Validation(
                "Watch fields must not contain control characters".to_string(),
            ));
        }
    }
    let api_base = validate_watch_base_url(&input.api_base)?;

    if let Some(ref existing_id) = input.id {
        let rec = state
            .watch_keys
            .iter_mut()
            .find(|r| &r.id == existing_id)
            .ok_or_else(|| WatchError::Validation("Watch entry no longer exists".to_string()))?;

        let new_key_opt = input
            .api_key
            .as_ref()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty());

        let target_changed =
            rec.model != model || rec.api_base != api_base || new_key_opt.is_some();
        rec.alias = alias;
        rec.model = model;
        rec.api_base = api_base;
        if let Some(raw_k) = new_key_opt {
            rec.api_key = encrypt_for_monitor_storage(&raw_k)?;
        }
        if target_changed {
            rec.rev += 1;
            rec.fail_streak = 0;
            rec.auth_fail_streak = 0;
            rec.auto_disabled_reason.clear();
            rec.last_probe = None;
        }
        return Ok(rec.id.clone());
    }

    if state.watch_keys.len() >= MAX_WATCHES {
        return Err(WatchError::Validation(format!(
            "Maximum {} watch credentials reached",
            MAX_WATCHES
        )));
    }
    let raw_key = input
        .api_key
        .as_ref()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| WatchError::Validation("API key is required for a new watch".to_string()))?;

    let stored_key = encrypt_for_monitor_storage(&raw_key)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let new_id = format!(
        "watch-{}",
        &sha256_hex(format!("{}:{}:{}", model, api_base, nanos).as_bytes())[..16]
    );

    state.watch_keys.push(WatchRecord {
        id: new_id.clone(),
        alias,
        model,
        api_base,
        api_key: stored_key,
        auto_enabled: false,
        auto_disabled_reason: String::new(),
        rev: 1,
        fail_streak: 0,
        auth_fail_streak: 0,
        next_probe_at: 0.0,
        cooldown_until: 0.0,
        last_probe: None,
        extra: BTreeMap::new(),
    });

    Ok(new_id)
}

#[derive(Clone, Deserialize)]
pub struct UpsertReserveInput {
    #[serde(default)]
    pub index: Option<usize>,
    pub model: String,
    pub api_base: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub note: String,
}

impl fmt::Debug for UpsertReserveInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpsertReserveInput")
            .field("index", &self.index)
            .field("model", &self.model)
            .field("api_base", &self.api_base)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("note", &self.note)
            .finish()
    }
}

pub fn upsert_reserve_record(
    state: &mut MonitorState,
    input: &UpsertReserveInput,
) -> Result<usize, WatchError> {
    let model = input.model.trim().to_string();
    let note = input.note.trim().to_string();
    if model.is_empty() {
        return Err(WatchError::Validation(
            "Reserve model cannot be empty".to_string(),
        ));
    }
    let api_base = validate_watch_base_url(&input.api_base)?;

    if let Some(idx) = input.index {
        let rec = state.spare_models.get_mut(idx).ok_or_else(|| {
            WatchError::Validation("Reserve entry index out of range".to_string())
        })?;
        rec.model = model;
        rec.api_base = api_base;
        rec.note = note;
        if let Some(raw_k) = input
            .api_key
            .as_ref()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
        {
            rec.api_key = encrypt_for_monitor_storage(&raw_k)?;
        }
        return Ok(idx);
    }

    let raw_key = input
        .api_key
        .as_ref()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            WatchError::Validation("API key is required for a new reserve model".to_string())
        })?;
    let stored_key = encrypt_for_monitor_storage(&raw_key)?;
    state.spare_models.push(SpareModelRecord {
        model,
        api_base,
        api_key: stored_key,
        note,
        extra: BTreeMap::new(),
    });
    Ok(state.spare_models.len() - 1)
}

/// Clones an existing Reserve model into the bounded Watchlist (`auto_enabled: false`) in Rust memory
/// so raw DPAPI credentials never cross IPC to the frontend WebView.
pub fn copy_reserve_into_watchlist(
    state: &mut MonitorState,
    reserve_index: usize,
    alias_override: Option<&str>,
    env_map: Option<&HashMap<String, String>>,
) -> Result<String, WatchError> {
    let reserve = state
        .spare_models
        .get(reserve_index)
        .ok_or_else(|| WatchError::Validation("Reserve entry index out of range".to_string()))?
        .clone();

    let api_base = validate_watch_base_url(&reserve.api_base)?;
    let resolved = resolve_secret(&reserve.api_key, env_map);
    if resolved.status != SecretStatus::SecretReady {
        return Err(WatchError::Validation(format!(
            "Reserve credential is not ready ({:?})",
            resolved.status
        )));
    }

    let target_model = reserve.model.trim();
    if let Some(existing) = state.watch_keys.iter().find(|w| {
        let same_model = w.model.trim() == target_model;
        let same_base = validate_watch_base_url(&w.api_base)
            .map(|b| b == api_base)
            .unwrap_or_else(|_| w.api_base.trim().trim_end_matches('/') == api_base);
        if !same_model || !same_base {
            return false;
        }
        if w.api_key.trim() == reserve.api_key.trim() {
            return true;
        }
        let w_resolved = resolve_secret(&w.api_key, env_map);
        w_resolved.status == SecretStatus::SecretReady && w_resolved.value == resolved.value
    }) {
        let label = if existing.alias.trim().is_empty() {
            existing.id.as_str()
        } else {
            existing.alias.trim()
        };
        return Err(WatchError::Validation(format!(
            "Reserve credential already exists in watchlist ('{}')",
            label
        )));
    }

    if state.watch_keys.len() >= MAX_WATCHES {
        return Err(WatchError::Validation(format!(
            "Maximum {} watch credentials reached",
            MAX_WATCHES
        )));
    }

    let raw_alias = alias_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let n = reserve.note.trim();
            if n.is_empty() {
                reserve.model.trim()
            } else {
                n
            }
        });
    let alias: String = raw_alias
        .chars()
        .filter(|&c| (c as u32) >= 32 && (c as u32) != 127)
        .take(120)
        .collect();

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let new_id = format!(
        "watch-{}",
        &sha256_hex(format!("{}:{}:{}", reserve.model, api_base, nanos).as_bytes())[..16]
    );

    state.watch_keys.push(WatchRecord {
        id: new_id.clone(),
        alias,
        model: reserve.model,
        api_base,
        api_key: reserve.api_key,
        auto_enabled: false,
        auto_disabled_reason: String::new(),
        rev: 1,
        fail_streak: 0,
        auth_fail_streak: 0,
        next_probe_at: 0.0,
        cooldown_until: 0.0,
        last_probe: None,
        extra: BTreeMap::new(),
    });

    Ok(new_id)
}

/// Clones an existing Watchlist credential into `spare_models` in Rust memory without exposing raw DPAPI keys over IPC.
pub fn copy_watch_into_reserve(
    state: &mut MonitorState,
    watch_id: &str,
    env_map: Option<&HashMap<String, String>>,
) -> Result<usize, WatchError> {
    let watch = state
        .watch_keys
        .iter()
        .find(|w| w.id == watch_id)
        .ok_or_else(|| WatchError::Validation(format!("Watch '{}' not found", watch_id)))?
        .clone();

    let api_base = validate_watch_base_url(&watch.api_base)?;
    let resolved = resolve_secret(&watch.api_key, env_map);
    if resolved.status != SecretStatus::SecretReady {
        return Err(WatchError::Validation(format!(
            "Watch credential is not ready ({:?})",
            resolved.status
        )));
    }

    let target_model = watch.model.trim();
    if state.spare_models.iter().any(|r| {
        let same_model = r.model.trim() == target_model;
        let same_base = validate_watch_base_url(&r.api_base)
            .map(|b| b == api_base)
            .unwrap_or_else(|_| r.api_base.trim().trim_end_matches('/') == api_base);
        if !same_model || !same_base {
            return false;
        }
        if r.api_key.trim() == watch.api_key.trim() {
            return true;
        }
        let r_resolved = resolve_secret(&r.api_key, env_map);
        r_resolved.status == SecretStatus::SecretReady && r_resolved.value == resolved.value
    }) {
        return Err(WatchError::Validation(format!(
            "Watch credential already exists in Reserve ('{}')",
            target_model
        )));
    }

    let note: String = watch
        .alias
        .trim()
        .chars()
        .filter(|&c| (c as u32) >= 32 && (c as u32) != 127)
        .take(120)
        .collect();

    state.spare_models.push(SpareModelRecord {
        model: watch.model,
        api_base,
        api_key: watch.api_key,
        note,
        extra: BTreeMap::new(),
    });
    Ok(state.spare_models.len() - 1)
}

pub fn set_watch_row_auto(
    state: &mut MonitorState,
    watch_id: &str,
    enabled: bool,
) -> Result<(), WatchError> {
    let rec = state
        .watch_keys
        .iter_mut()
        .find(|w| w.id == watch_id)
        .ok_or_else(|| WatchError::Validation(format!("Watch '{}' not found", watch_id)))?;
    rec.auto_enabled = enabled;
    if enabled {
        rec.auto_disabled_reason.clear();
        rec.auth_fail_streak = 0;
    }
    Ok(())
}

/// Applies a probe result to a `WatchRecord`, enforcing exponential backoff (cap 60m) and 2x 401/403 auto-disable.
pub fn record_watch_probe_outcome(
    record: &mut WatchRecord,
    outcome: ProbeOutcome,
    interval_secs: f64,
) -> Option<AutoDisabledAlert> {
    let now = outcome.at;
    let status = outcome.status_code;
    record.last_probe = Some(outcome.clone());

    if outcome.ok {
        record.fail_streak = 0;
        record.auth_fail_streak = 0;
        record.cooldown_until = 0.0;
        record.next_probe_at = now + interval_secs.max(60.0);
        return None;
    }

    record.fail_streak = record.fail_streak.saturating_add(1);
    let exp_factor = 1u32 << record.fail_streak.min(10);
    let backoff = (interval_secs.max(60.0) * (exp_factor as f64)).min(BACKOFF_CAP_SECS);
    record.cooldown_until = now + backoff;
    record.next_probe_at = record.cooldown_until;

    if matches!(status, Some(401 | 403)) {
        record.auth_fail_streak = record.auth_fail_streak.saturating_add(1);
        if record.auth_fail_streak >= 2 && record.auto_enabled {
            let code = status.unwrap_or(401);
            record.auto_enabled = false;
            record.auto_disabled_reason =
                format!("Auto-disabled after 2 consecutive HTTP {}", code);
            return Some(AutoDisabledAlert {
                watch_id: record.id.clone(),
                alias: if record.alias.is_empty() {
                    record.model.clone()
                } else {
                    record.alias.clone()
                },
                model: record.model.clone(),
                status_code: code,
            });
        }
    } else {
        record.auth_fail_streak = 0;
    }

    None
}

static WATCH_HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn watch_http_client() -> Option<&'static reqwest::Client> {
    if let Some(c) = WATCH_HTTP_CLIENT.get() {
        return Some(c);
    }
    let built = reqwest::Client::builder()
        .timeout(Duration::from_millis(WATCH_PROBE_TIMEOUT_MS))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent("OpenViking-Monitor/1.0")
        .build()
        .ok()?;
    let _ = WATCH_HTTP_CLIENT.set(built);
    WATCH_HTTP_CLIENT.get()
}

/// Executes a bounded chat-completions probe (`20s` timeout, `max_tokens: 64`, zero redirect, Monitor UA).
/// Never logs or persists response bodies or bearer secrets.
pub async fn probe_watch_credential(
    model: &str,
    api_base: &str,
    raw_secret: &str,
    env_map: Option<&HashMap<String, String>>,
) -> ProbeOutcome {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let resolved = resolve_secret(raw_secret, env_map);
    if resolved.status != SecretStatus::SecretReady {
        return ProbeOutcome {
            ok: false,
            category: "secret_error".to_string(),
            status_code: None,
            ms: None,
            at: now,
        };
    }

    let clean_base = match validate_watch_base_url(api_base) {
        Ok(b) => b,
        Err(_) => {
            return ProbeOutcome {
                ok: false,
                category: "invalid_url".to_string(),
                status_code: None,
                ms: None,
                at: now,
            };
        }
    };

    let Some(client) = watch_http_client() else {
        return ProbeOutcome {
            ok: false,
            category: "client_error".to_string(),
            status_code: None,
            ms: None,
            at: now,
        };
    };

    let url = format!("{}/chat/completions", clean_base);
    let body = json!({
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": WATCH_MAX_TOKENS,
        "temperature": 0
    });

    let start = Instant::now();
    match client
        .post(&url)
        .bearer_auth(&resolved.value)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            let ms = start.elapsed().as_millis() as u64;
            let code = resp.status().as_u16();
            if resp.status().is_success() {
                ProbeOutcome {
                    ok: true,
                    category: "ok".to_string(),
                    status_code: Some(code),
                    ms: Some(ms),
                    at: now,
                }
            } else {
                let cat = match code {
                    401 | 403 => "auth",
                    402 | 429 => "quota",
                    400 | 404 | 422 => "request",
                    _ if code >= 500 => "upstream",
                    _ => "http_error",
                };
                ProbeOutcome {
                    ok: false,
                    category: cat.to_string(),
                    status_code: Some(code),
                    ms: Some(ms),
                    at: now,
                }
            }
        }
        Err(e) => {
            let ms = start.elapsed().as_millis() as u64;
            ProbeOutcome {
                ok: false,
                category: if e.is_timeout() {
                    "timeout".to_string()
                } else {
                    "network".to_string()
                },
                status_code: None,
                ms: Some(ms),
                at: now,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_watch_capacity_url_validation_and_redacted_summary() {
        let mut state = MonitorState::default();

        // Remote HTTP must be rejected
        let bad_http = upsert_watch_record(
            &mut state,
            &UpsertWatchInput {
                id: None,
                alias: "remote-http".to_string(),
                model: "m1".to_string(),
                api_base: "http://api.example.com/v1".to_string(),
                api_key: Some("SYNTHETIC_WATCH_SECRET_1".to_string()),
            },
        );
        assert!(bad_http.is_err());

        // Loopback HTTP ending with /v1 is allowed
        for idx in 0..MAX_WATCHES {
            upsert_watch_record(
                &mut state,
                &UpsertWatchInput {
                    id: None,
                    alias: format!("k{}", idx),
                    model: "m-local".to_string(),
                    api_base: "http://127.0.0.1:20128/v1".to_string(),
                    api_key: Some(format!("SYNTHETIC_WATCH_SECRET_{}", idx)),
                },
            )
            .expect("insert watch up to 4");
        }

        // 5th credential must fail closed
        let overflow = upsert_watch_record(
            &mut state,
            &UpsertWatchInput {
                id: None,
                alias: "k5".to_string(),
                model: "m-local".to_string(),
                api_base: "http://127.0.0.1:20128/v1".to_string(),
                api_key: Some("SYNTHETIC_WATCH_SECRET_5".to_string()),
            },
        );
        assert!(overflow.is_err());

        // Legacy 6-key file must still load cleanly and allow shrinking via delete
        let dir = tempdir().expect("tempdir");
        let mon_path = dir.path().join("monitor.json");
        let bk_dir = dir.path().join("backups");
        let mut legacy = MonitorState {
            watch_interval_minutes: 15,
            ..MonitorState::default()
        };
        for idx in 0..6 {
            legacy.watch_keys.push(WatchRecord {
                id: format!("watch-legacy-{}", idx),
                alias: format!("Legacy {}", idx),
                model: "m-leg".to_string(),
                api_base: "https://api.example.com/v1".to_string(),
                api_key: "SYNTHETIC_LEG".to_string(),
                auto_enabled: false,
                auto_disabled_reason: String::new(),
                rev: 1,
                fail_streak: 0,
                auth_fail_streak: 0,
                next_probe_at: 0.0,
                cooldown_until: 0.0,
                last_probe: None,
                extra: BTreeMap::new(),
            });
        }
        let raw_legacy = serde_json::to_string_pretty(&legacy).unwrap();
        assert!(raw_legacy.contains("\"watch_auto_minutes\": 15"));
        fs::write(&mon_path, &raw_legacy).unwrap();
        let (mut loaded_leg, leg_sha) = load_monitor_state(&mon_path).expect("load 6-key legacy");
        assert_eq!(loaded_leg.watch_keys.len(), 6);
        assert_eq!(loaded_leg.watch_interval_minutes, 15);
        loaded_leg.watch_keys.pop();
        save_monitor_state(&mon_path, &bk_dir, &loaded_leg, &leg_sha)
            .expect("shrinking legacy 6 -> 5 must succeed");

        // Stored keys on Windows must be DPAPI-encrypted and never leak in summary JSON
        #[cfg(windows)]
        assert!(state.watch_keys[0].api_key.starts_with("dpapi:"));

        let summary = summarize_monitor_state(&state, "sha-test", None);
        let json_out = serde_json::to_string(&summary).expect("serialize summary");
        assert!(!json_out.contains("SYNTHETIC_WATCH_SECRET_0"));
        assert!(!json_out.contains("dpapi:"));
    }

    #[test]
    fn test_consecutive_401_auto_disable_and_alert_free_of_secrets() {
        let mut rec = WatchRecord {
            id: "watch-1".to_string(),
            alias: "Backup Gateway".to_string(),
            model: "gpt-test".to_string(),
            api_base: "https://api.example.com/v1".to_string(),
            api_key: "SUPER_SECRET_NEVER_LEAK".to_string(),
            auto_enabled: true,
            auto_disabled_reason: String::new(),
            rev: 1,
            fail_streak: 0,
            auth_fail_streak: 0,
            next_probe_at: 0.0,
            cooldown_until: 0.0,
            last_probe: None,
            extra: BTreeMap::new(),
        };

        // 1st 401 keeps Auto enabled
        let alert1 = record_watch_probe_outcome(
            &mut rec,
            ProbeOutcome {
                ok: false,
                category: "auth".to_string(),
                status_code: Some(401),
                ms: Some(120),
                at: 1000.0,
            },
            60.0,
        );
        assert!(alert1.is_none());
        assert!(rec.auto_enabled);
        assert_eq!(rec.auth_fail_streak, 1);

        // 2nd consecutive 403 disables Auto and emits clean alert
        let alert2 = record_watch_probe_outcome(
            &mut rec,
            ProbeOutcome {
                ok: false,
                category: "auth".to_string(),
                status_code: Some(403),
                ms: Some(115),
                at: 1100.0,
            },
            60.0,
        )
        .expect("2nd auth failure must trigger alert");
        assert!(!rec.auto_enabled);
        assert_eq!(alert2.alias, "Backup Gateway");
        assert_eq!(alert2.status_code, 403);
        let alert_json = serde_json::to_string(&alert2).unwrap();
        assert!(!alert_json.contains("SUPER_SECRET_NEVER_LEAK"));
    }

    #[test]
    fn test_corrupted_monitor_json_fails_closed_preserving_bytes() {
        let dir = tempdir().expect("tempdir");
        let mon_path = dir.path().join("monitor.json");
        let corrupted = b"{not-valid-json!!!";
        fs::write(&mon_path, corrupted).expect("write damaged monitor.json");

        let err = load_monitor_state(&mon_path);
        assert!(matches!(err, Err(WatchError::CorruptedState(_))));
        assert_eq!(fs::read(&mon_path).unwrap(), corrupted);
    }

    #[test]
    fn test_reserve_crud_and_watch_auto_toggle_roundtrip() {
        let mut state = MonitorState::default();
        let idx = upsert_reserve_record(
            &mut state,
            &UpsertReserveInput {
                index: None,
                model: "spare-v1".to_string(),
                api_base: "https://api.example.com/v1".to_string(),
                api_key: Some("SYNTHETIC_SPARE_SECRET_42".to_string()),
                note: "Fallback pool".to_string(),
            },
        )
        .expect("insert reserve");
        assert_eq!(idx, 0);

        let wid = upsert_watch_record(
            &mut state,
            &UpsertWatchInput {
                id: None,
                alias: "row1".to_string(),
                model: "m1".to_string(),
                api_base: "https://api.example.com/v1".to_string(),
                api_key: Some("SYNTHETIC_WATCH_KEY_42".to_string()),
            },
        )
        .expect("insert watch");

        set_watch_row_auto(&mut state, &wid, true).expect("enable auto");
        assert!(state.watch_keys[0].auto_enabled);

        let summary = summarize_monitor_state(&state, "sha-r", None);
        assert!(summary.notify_on_down);
        assert!(summary.notify_on_failover);
        assert_eq!(summary.watch_interval_minutes, 10);
        assert_eq!(summary.reserves.len(), 1);
        verify_reserves_sha(&state.spare_models, &summary.reserves_sha256)
            .expect("matching reserves_sha256 must pass");
        assert!(matches!(
            verify_reserves_sha(&state.spare_models, "stale-reserves-sha"),
            Err(WatchError::RevisionConflict { .. })
        ));
        assert_eq!(summary.reserves[0].model, "spare-v1");
        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(!serialized.contains("SYNTHETIC_SPARE_SECRET_42"));

        let copied_id = copy_reserve_into_watchlist(&mut state, 0, None, None)
            .expect("copy reserve into watchlist");
        let copied = state
            .watch_keys
            .iter()
            .find(|w| w.id == copied_id)
            .expect("copied watch record");
        assert_eq!(copied.model, "spare-v1");
        assert_eq!(copied.alias, "Fallback pool");
        assert!(!copied.auto_enabled);
        assert_eq!(copied.api_key, state.spare_models[0].api_key);

        let dup_err = copy_reserve_into_watchlist(&mut state, 0, None, None)
            .expect_err("duplicate copy must be rejected");
        assert!(dup_err.to_string().contains("already exists in watchlist"));
        assert!(!dup_err.to_string().contains("SYNTHETIC_SPARE_SECRET_42"));

        state.watch_keys.retain(|w| w.id != copied_id);
        upsert_watch_record(
            &mut state,
            &UpsertWatchInput {
                id: None,
                alias: "Manual same key".to_string(),
                model: "spare-v1".to_string(),
                api_base: "https://api.example.com/v1/".to_string(),
                api_key: Some("SYNTHETIC_SPARE_SECRET_42".to_string()),
            },
        )
        .expect("insert manual watch with distinct DPAPI salt");
        let cross_salt_dup = copy_reserve_into_watchlist(&mut state, 0, None, None)
            .expect_err("cross-salt identical secret must also be rejected");
        assert!(cross_salt_dup.to_string().contains("Manual same key"));

        let res_idx = copy_watch_into_reserve(&mut state, &wid, None)
            .expect("copy distinct watch credential into reserve");
        assert_eq!(state.spare_models[res_idx].model, "m1");
        assert_eq!(state.spare_models[res_idx].note, "row1");
        assert!(copy_watch_into_reserve(&mut state, &wid, None).is_err());

        // Verify monitor-state retention pruning caps snapshots at MAX_MONITOR_STATE_BACKUPS
        let tmp = tempdir().expect("tempdir");
        let mon_file = tmp.path().join("monitor.json");
        let bak_dir = tmp.path().join("backups");
        let mut sha = "<absent>".to_string();
        for n in 1..=35u32 {
            state.watch_interval_minutes = n;
            sha = save_monitor_state(&mon_file, &bak_dir, &state, &sha).expect("save revision");
        }
        let kept_count = fs::read_dir(bak_dir.join("monitor-state"))
            .expect("read monitor-state")
            .count();
        assert_eq!(kept_count, MAX_MONITOR_STATE_BACKUPS);
    }

    #[test]
    fn test_window_geometry_parse_and_format() {
        assert_eq!(
            parse_window_geometry("1020x640"),
            Some(WindowGeometry {
                width: 1020,
                height: 640,
                x: None,
                y: None,
            })
        );
        assert_eq!(
            parse_window_geometry("1280x860+140+90"),
            Some(WindowGeometry {
                width: 1280,
                height: 860,
                x: Some(140),
                y: Some(90),
            })
        );
        assert_eq!(
            parse_window_geometry("1100x720+-480+60"),
            Some(WindowGeometry {
                width: 1100,
                height: 720,
                x: Some(-480),
                y: Some(60),
            })
        );
        assert_eq!(
            parse_window_geometry("640x400+20+30"),
            Some(WindowGeometry {
                width: MIN_WINDOW_WIDTH,
                height: MIN_WINDOW_HEIGHT,
                x: Some(20),
                y: Some(30),
            })
        );
        assert_eq!(
            parse_window_geometry("1200x840+-32000+-32000"),
            Some(WindowGeometry {
                width: 1200,
                height: 840,
                x: None,
                y: None,
            })
        );
        assert_eq!(
            format_window_geometry(1200, 840, Some(-32000), Some(-32000)),
            None
        );
        assert_eq!(
            format_window_geometry(1200, 840, Some(-320), Some(48)).as_deref(),
            Some("1200x840+-320+48")
        );
    }
}
