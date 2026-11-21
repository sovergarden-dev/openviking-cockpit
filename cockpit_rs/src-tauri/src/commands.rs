//! Tauri V2 IPC command handlers.
//! Every blocking disk/DPAPI/lock operation runs inside `spawn_blocking` (`tauri.A1`).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, State};

use cockpit_rs::config::conf_gate::{
    apply_slot_update_with_live_policy, delete_fallback_slot_with_live_policy, display_clean_path,
    load_raw_config, normalize_endpoint, reorder_slot_with_live_policy,
    resolve_server_root_api_key, resolve_slot_audit_target, resolve_slot_raw_credential,
    summarize_config_with_audits, update_failback_policy_with_live_policy, ApplySlotOutcome,
    CachedAuditVerdict, ConfigSummary, SlotReorderOp, SlotUpdateInput, AUDIT_TTL_FAILOVER_S,
    AUDIT_TTL_PRIMARY_S,
};
use cockpit_rs::secrets::secret_store::{is_env_ref, resolve_secret, SecretStatus};
use cockpit_rs::services::auditor::{run_provider_audit, AuditReportDocument};
use cockpit_rs::services::auditor_cache::{
    load_cached_audit_document, load_cached_audit_verdict, presentation_sanitize_text,
};
use cockpit_rs::services::provider_probe::{
    list_provider_models as fetch_provider_models, probe_chat_model,
    run_provider_benchmark as execute_provider_benchmark, validate_provider_probe_url,
    BenchmarkModelSummary, BenchmarkProgressEvent, ProviderModelsResult, DEFAULT_PROBE_TIMEOUT_MS,
};
use cockpit_rs::services::service_control::{execute_service_step, ServiceAction};
use cockpit_rs::services::storage_inspector::{
    inspect_storage_footprint, read_allowed_log_tail, LogTailOutcome, StorageFootprint,
};
use cockpit_rs::services::telemetry::{
    evaluate_telemetry_incidents_with_uptime, read_lifecycle_summary, EndpointStatus,
    LifecycleSummary, MemoriesStatsResponse, RetrievalObserverResponse, SearchFindHit,
    SearchFindRequest, TelemetrySnapshot, VikingDbResponse, VlmActiveResponse,
};
use cockpit_rs::services::watchlist::{
    copy_reserve_into_watchlist, copy_watch_into_reserve, load_monitor_state,
    probe_watch_credential, record_watch_probe_outcome, save_monitor_state_with_live_policy,
    set_reserve_probe_outcome, set_watch_row_auto, summarize_monitor_state_with_audits,
    upsert_reserve_record, upsert_slot_credential_into_reserve,
    upsert_slot_credential_into_watchlist, upsert_watch_record, verify_reserves_sha,
    AutoDisabledAlert, MonitorState, MonitorStateSummary, ProbeOutcome, SpareModelRecord,
    UpsertReserveInput, UpsertWatchInput,
};

use crate::state::{CockpitPaths, CockpitState};

fn file_stamp(path: &std::path::Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    Some((modified, meta.len()))
}

fn is_isolated_ov_home() -> bool {
    std::env::var_os("COCKPIT_OV_HOME").is_some()
}

fn windows_startup_lnk_path() -> Option<std::path::PathBuf> {
    if is_isolated_ov_home() {
        return None;
    }
    std::env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .map(|p| {
            p.join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup")
                .join("OpenViking Monitor.lnk")
        })
}

fn effective_startup_enabled(st: &MonitorState) -> bool {
    if let Some(lnk) = windows_startup_lnk_path() {
        lnk.is_file()
    } else {
        st.run_with_windows
    }
}

#[cfg(windows)]
fn sync_windows_startup_shortcut(enabled: bool, ov_home: &std::path::Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let Some(lnk_path) = windows_startup_lnk_path() else {
        return Ok(());
    };
    if !enabled {
        if lnk_path.exists() {
            std::fs::remove_file(&lnk_path)
                .map_err(|e| format!("Failed to remove Startup shortcut: {}", e))?;
        }
        return Ok(());
    }

    let monitor_dir = ov_home.join("monitor");
    let live_exe = monitor_dir.join("openviking-cockpit.exe");
    let target_exe = if live_exe.is_file() {
        live_exe
    } else {
        std::env::current_exe().map_err(|e| format!("Failed to locate executable: {}", e))?
    };
    let work_dir = target_exe.parent().unwrap_or(&monitor_dir).to_path_buf();
    let icon_path = monitor_dir.join("openviking.ico");

    let sys_ps = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .map(|r| {
            r.join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        })
        .filter(|p| p.is_file())
        .unwrap_or_else(|| std::path::PathBuf::from("powershell.exe"));

    let script = "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut($env:COCKPIT_LNK_PATH); $sc.TargetPath = $env:COCKPIT_TARGET_EXE; $sc.Arguments = '--tray'; $sc.WorkingDirectory = $env:COCKPIT_WORK_DIR; if ($env:COCKPIT_ICON_PATH -and (Test-Path -LiteralPath $env:COCKPIT_ICON_PATH)) { $sc.IconLocation = $env:COCKPIT_ICON_PATH }; $sc.Save()";

    let out = std::process::Command::new(sys_ps)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("COCKPIT_LNK_PATH", &lnk_path)
        .env("COCKPIT_TARGET_EXE", &target_exe)
        .env("COCKPIT_WORK_DIR", &work_dir)
        .env("COCKPIT_ICON_PATH", &icon_path)
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("Failed to invoke PowerShell for Startup shortcut: {}", e))?;

    if !out.status.success() || !lnk_path.is_file() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "Failed to write Startup shortcut: {}",
            stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn sync_windows_startup_shortcut(_enabled: bool, _ov_home: &std::path::Path) -> Result<(), String> {
    Ok(())
}

fn build_monitor_summary(
    paths: &CockpitPaths,
    st: &MonitorState,
    sha: &str,
) -> MonitorStateSummary {
    let mut summary =
        summarize_monitor_state_with_audits(st, sha, None, Some(&paths.security_reports_dir));
    summary.run_with_windows = effective_startup_enabled(st);
    summary
}

async fn read_cached_poll_meta(
    state: &Arc<CockpitState>,
) -> (Option<String>, bool, bool, Option<LifecycleSummary>) {
    let state_ref = Arc::clone(state);
    tauri::async_runtime::spawn_blocking(move || {
        let cur_conf_stamp = file_stamp(&state_ref.paths.conf_path);
        let cur_mon_stamp = file_stamp(&state_ref.paths.monitor_json_path);
        let cur_life_stamp = file_stamp(&state_ref.paths.lifecycle_log_path);

        let prev = state_ref
            .poll_meta_cache
            .lock()
            .ok()
            .map(|g| g.clone())
            .unwrap_or_default();

        let conf_dirty = cur_conf_stamp != prev.conf_stamp;
        let mon_dirty = cur_mon_stamp != prev.monitor_stamp;
        let life_dirty = cur_life_stamp != prev.lifecycle_stamp;
        if !conf_dirty
            && !mon_dirty
            && !life_dirty
            && (cur_conf_stamp.is_some() || cur_mon_stamp.is_some() || cur_life_stamp.is_some())
        {
            return (
                prev.expected_embedding_model,
                prev.notify_on_down,
                prev.notify_on_failover,
                prev.lifecycle_summary,
            );
        }

        let expected_emb = if conf_dirty {
            if cur_conf_stamp.is_some() {
                if let Ok((cfg, _, _)) = load_raw_config(&state_ref.paths.conf_path) {
                    state_ref
                        .telemetry_client
                        .set_api_key(resolve_server_root_api_key(&cfg, None));
                    cfg.embedding
                        .as_ref()
                        .and_then(|e| e.get("dense").or(Some(e)))
                        .and_then(|d| d.get("model"))
                        .and_then(|m| m.as_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            } else {
                state_ref.telemetry_client.set_api_key(None);
                None
            }
        } else {
            prev.expected_embedding_model
        };

        let (notify_on_down, notify_on_failover) = if mon_dirty {
            if cur_mon_stamp.is_some() {
                load_monitor_state(&state_ref.paths.monitor_json_path)
                    .map(|(st, _)| (st.notify_on_down, st.notify_on_failover))
                    .unwrap_or((true, true))
            } else {
                (true, true)
            }
        } else {
            (prev.notify_on_down, prev.notify_on_failover)
        };

        let lifecycle_summary = if life_dirty {
            if cur_life_stamp.is_some() {
                read_lifecycle_summary(&state_ref.paths.lifecycle_log_path)
            } else {
                None
            }
        } else {
            prev.lifecycle_summary
        };

        if let Ok(mut guard) = state_ref.poll_meta_cache.lock() {
            guard.conf_stamp = cur_conf_stamp;
            guard.expected_embedding_model = expected_emb.clone();
            guard.monitor_stamp = cur_mon_stamp;
            guard.notify_on_down = notify_on_down;
            guard.notify_on_failover = notify_on_failover;
            guard.lifecycle_stamp = cur_life_stamp;
            guard.lifecycle_summary = lifecycle_summary.clone();
        }

        (
            expected_emb,
            notify_on_down,
            notify_on_failover,
            lifecycle_summary,
        )
    })
    .await
    .unwrap_or((None, true, true, None))
}

pub async fn collect_telemetry_once(state: &Arc<CockpitState>) -> TelemetrySnapshot {
    let (expected_emb, notify_on_down, notify_on_failover, lifecycle_summary) =
        read_cached_poll_meta(state).await;

    let mut snapshot = state
        .telemetry_client
        .fetch_snapshot_with_embedding(expected_emb.as_deref())
        .await;
    snapshot.lifecycle = lifecycle_summary;

    let uptime_secs = state.started_at.elapsed().as_secs();
    let alerts = state
        .incident_tracker
        .lock()
        .ok()
        .map(|mut tracker| {
            evaluate_telemetry_incidents_with_uptime(
                &mut tracker,
                &snapshot,
                notify_on_down,
                notify_on_failover,
                uptime_secs,
            )
        })
        .unwrap_or_default();

    if !alerts.is_empty() {
        tauri::async_runtime::spawn_blocking(move || {
            for (title, body) in alerts {
                crate::dispatch_tray_balloon(&title, &body);
            }
        });
    }

    state.broadcast_snapshot(&snapshot);
    snapshot
}

/// Runs one sequential pass over due `auto_enabled` watch entries (`COCKPIT_RUST_SPEC` §4.3).
pub async fn run_due_watch_auto_pass(app: &AppHandle, state: &Arc<CockpitState>) {
    let mon_path = state.paths.monitor_json_path.clone();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let due_targets = tauri::async_runtime::spawn_blocking(move || {
        let Ok((st, _)) = load_monitor_state(&mon_path) else {
            return Vec::new();
        };
        if !st.watch_auto_enabled {
            return Vec::new();
        }
        let interval_secs = (st.watch_interval_minutes.max(1) as f64) * 60.0;
        st.watch_keys
            .into_iter()
            .filter(|w| {
                w.auto_enabled
                    && !w.api_key.trim().is_empty()
                    && now >= w.next_probe_at
                    && now >= w.cooldown_until
            })
            .map(|w| (w.id, w.model, w.api_base, w.api_key, w.rev, interval_secs))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();

    for (wid, model, api_base, raw_key, start_rev, interval_secs) in due_targets {
        let outcome = probe_watch_credential(&model, &api_base, &raw_key, None).await;
        let paths = state.paths.clone();
        let saved_result = {
            let _guard = state.monitor_lock.lock().await;
            tauri::async_runtime::spawn_blocking(
                move || -> Option<(MonitorStateSummary, Option<AutoDisabledAlert>)> {
                    let (mut st, cur_sha) = load_monitor_state(&paths.monitor_json_path).ok()?;
                    if !st.watch_auto_enabled {
                        return None;
                    }
                    let rec = st
                        .watch_keys
                        .iter_mut()
                        .find(|w| w.id == wid && w.rev == start_rev && w.auto_enabled)?;
                    let alert = record_watch_probe_outcome(rec, outcome, interval_secs);
                    let new_sha = save_monitor_state_with_live_policy(
                        &paths.monitor_json_path,
                        &paths.backups_dir,
                        &st,
                        &cur_sha,
                        true,
                    )
                    .ok()?;
                    let summary = build_monitor_summary(&paths, &st, &new_sha);
                    Some((summary, alert))
                },
            )
            .await
            .ok()
            .flatten()
        };

        if let Some((summary, maybe_alert)) = saved_result {
            state.invalidate_poll_meta_cache();
            let _ = app.emit("monitor://updated", &summary);
            if let Some(alert) = maybe_alert {
                let _ = app.emit("watchlist://auto-disabled", &alert);
                tauri::async_runtime::spawn_blocking(move || {
                    crate::dispatch_watch_auto_disabled_balloon(
                        &alert.alias,
                        &alert.model,
                        alert.status_code,
                    );
                });
            }
        }
    }
}

#[tauri::command]
pub async fn get_telemetry_status(
    state: State<'_, Arc<CockpitState>>,
) -> Result<TelemetrySnapshot, String> {
    Ok(collect_telemetry_once(state.inner()).await)
}

#[tauri::command]
pub async fn subscribe_telemetry_channel(
    state: State<'_, Arc<CockpitState>>,
    on_event: Channel<TelemetrySnapshot>,
) -> Result<(), String> {
    let cached = state.latest_snapshot.read().ok().and_then(|g| g.clone());
    if let Some(snap) = cached {
        let _ = on_event.send(snap);
    }
    let mut subs = state
        .subscribers
        .lock()
        .map_err(|_| "Telemetry subscriber lock poisoned".to_string())?;
    subs.push(on_event);
    Ok(())
}

#[tauri::command]
pub async fn switch_active_slot(
    state: State<'_, Arc<CockpitState>>,
    slot_index: usize,
) -> Result<VlmActiveResponse, String> {
    let _ = read_cached_poll_meta(state.inner()).await;
    let res = state
        .telemetry_client
        .switch_active_vlm_slot(slot_index)
        .await?;
    let _ = collect_telemetry_once(state.inner()).await;
    Ok(res)
}

#[tauri::command]
pub async fn read_config(state: State<'_, Arc<CockpitState>>) -> Result<ConfigSummary, String> {
    let paths = state.paths.clone();
    let live_vlm = state.latest_snapshot.read().ok().and_then(|g| {
        g.as_ref()
            .and_then(|s| s.vlm.as_ref())
            .and_then(|v| v.result.clone())
    });

    tauri::async_runtime::spawn_blocking(move || {
        let (cfg, _, sha) = load_raw_config(&paths.conf_path).map_err(|e| e.to_string())?;
        Ok(summarize_config_with_audits(
            &paths.conf_path,
            &cfg,
            &sha,
            live_vlm.as_ref(),
            None,
            Some(&paths.security_reports_dir),
        ))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[derive(Clone, serde::Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum CredentialSource {
    Slot {
        slot_index: usize,
    },
    Watch {
        watch_id: String,
    },
    Reserve {
        index: usize,
    },
    Inline {
        api_base: String,
        #[serde(default)]
        api_key: Option<String>,
    },
}

impl std::fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Slot { slot_index } => f
                .debug_struct("Slot")
                .field("slot_index", slot_index)
                .finish(),
            Self::Watch { watch_id } => {
                f.debug_struct("Watch").field("watch_id", watch_id).finish()
            }
            Self::Reserve { index } => f.debug_struct("Reserve").field("index", index).finish(),
            Self::Inline { api_base, api_key } => f
                .debug_struct("Inline")
                .field("api_base", api_base)
                .field("api_key", &api_key.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

struct ResolvedCredentialData {
    api_base: String,
    resolved_key: String,
    raw_key: String,
    default_model: Option<String>,
}

fn resolve_credential_source(
    paths: &CockpitPaths,
    source: &CredentialSource,
) -> Result<ResolvedCredentialData, String> {
    match source {
        CredentialSource::Slot { slot_index } => {
            let (cfg, _, _) = load_raw_config(&paths.conf_path).map_err(|e| e.to_string())?;
            let (model, api_base, raw_key, sec) =
                resolve_slot_raw_credential(&cfg, *slot_index, None).map_err(|e| e.to_string())?;
            Ok(ResolvedCredentialData {
                api_base,
                resolved_key: sec.value,
                raw_key,
                default_model: Some(model),
            })
        }
        CredentialSource::Watch { watch_id } => {
            let (st, _) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            let rec = st
                .watch_keys
                .iter()
                .find(|w| w.id == *watch_id)
                .ok_or_else(|| format!("Watch '{}' not found", watch_id))?;
            let sec = resolve_secret(&rec.api_key, None);
            if sec.status != SecretStatus::SecretReady {
                return Err(format!("Watch credential not ready: {:?}", sec.status));
            }
            Ok(ResolvedCredentialData {
                api_base: rec.api_base.clone(),
                resolved_key: sec.value,
                raw_key: rec.api_key.clone(),
                default_model: Some(rec.model.clone()),
            })
        }
        CredentialSource::Reserve { index } => {
            let (st, _) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            let rec = st
                .spare_models
                .get(*index)
                .ok_or_else(|| format!("Reserve index {} out of range", index))?;
            let sec = resolve_secret(&rec.api_key, None);
            if sec.status != SecretStatus::SecretReady {
                return Err(format!("Reserve credential not ready: {:?}", sec.status));
            }
            Ok(ResolvedCredentialData {
                api_base: rec.api_base.clone(),
                resolved_key: sec.value,
                raw_key: rec.api_key.clone(),
                default_model: Some(rec.model.clone()),
            })
        }
        CredentialSource::Inline { api_base, api_key } => {
            let clean_base = validate_provider_probe_url(api_base)?;
            let raw_trimmed = api_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("");
            if raw_trimmed.starts_with("dpapi:") {
                return Err(
                    "Do not supply raw dpapi: strings; select a saved source or enter plaintext / ${ENV_VAR}"
                        .to_string(),
                );
            }
            if raw_trimmed.is_empty() {
                return Ok(ResolvedCredentialData {
                    api_base: clean_base,
                    resolved_key: String::new(),
                    raw_key: String::new(),
                    default_model: None,
                });
            }
            let sec = resolve_secret(raw_trimmed, None);
            if sec.status != SecretStatus::SecretReady {
                return Err(format!("Inline credential not ready: {:?}", sec.status));
            }
            Ok(ResolvedCredentialData {
                api_base: clean_base,
                resolved_key: sec.value,
                raw_key: raw_trimmed.to_string(),
                default_model: None,
            })
        }
    }
}

fn resolve_inherited_key_for_endpoint(
    paths: &CockpitPaths,
    inherit_source: Option<&CredentialSource>,
    target_base: &str,
) -> Result<Option<String>, String> {
    let Some(source) = inherit_source else {
        return Ok(None);
    };
    let resolved = resolve_credential_source(paths, source)?;
    if normalize_endpoint(&resolved.api_base) != normalize_endpoint(target_base) {
        return Err(
            "Selected key source belongs to a different Base URL; enter API key explicitly"
                .to_string(),
        );
    }
    if resolved.resolved_key.trim().is_empty() {
        return Err("Selected key source has no usable API key".to_string());
    }
    let key_for_save = if is_env_ref(resolved.raw_key.trim()) {
        resolved.raw_key.trim().to_string()
    } else {
        resolved.resolved_key
    };
    Ok(Some(key_for_save))
}

fn lookup_failover_cached_audit(
    reports_dir: &std::path::Path,
    api_base: &str,
    model: &str,
    resolved_key: &str,
) -> Option<CachedAuditVerdict> {
    load_cached_audit_verdict(
        reports_dir,
        api_base,
        model,
        resolved_key,
        AUDIT_TTL_FAILOVER_S,
    )
}

fn find_reserve_fallback_index(
    reserves: &[SpareModelRecord],
    model: &str,
    api_base: &str,
    raw_key: &str,
) -> Option<usize> {
    let ep = normalize_endpoint(api_base);
    reserves
        .iter()
        .position(|r| {
            r.model == model && normalize_endpoint(&r.api_base) == ep && r.api_key == raw_key
        })
        .or_else(|| {
            reserves
                .iter()
                .position(|r| r.model == model && normalize_endpoint(&r.api_base) == ep)
        })
}

#[tauri::command]
pub async fn apply_slot(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    mut input: SlotUpdateInput,
    inherit_source: Option<CredentialSource>,
) -> Result<ApplySlotOutcome, String> {
    let paths = state.paths.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        if input.api_key.as_deref().is_none_or(|k| k.trim().is_empty()) {
            if let Some(inherited) = resolve_inherited_key_for_endpoint(
                &paths,
                inherit_source.as_ref(),
                &input.api_base,
            )? {
                input.api_key = Some(inherited);
            }
        }
        apply_slot_update_with_live_policy(
            &paths.conf_path,
            &paths.backups_dir,
            &expected_sha,
            &input,
            None,
            Some(&paths.security_reports_dir),
            true,
            |api_base, model, resolved_key| {
                lookup_failover_cached_audit(
                    &paths.security_reports_dir,
                    api_base,
                    model,
                    resolved_key,
                )
            },
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;
    state.invalidate_poll_meta_cache();
    Ok(res)
}

#[tauri::command]
pub async fn reorder_slot(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    op: SlotReorderOp,
) -> Result<ApplySlotOutcome, String> {
    let paths = state.paths.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        reorder_slot_with_live_policy(
            &paths.conf_path,
            &paths.backups_dir,
            &expected_sha,
            &op,
            None,
            Some(&paths.security_reports_dir),
            true,
            |api_base, model, resolved_key| {
                lookup_failover_cached_audit(
                    &paths.security_reports_dir,
                    api_base,
                    model,
                    resolved_key,
                )
            },
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;
    state.invalidate_poll_meta_cache();
    Ok(res)
}

#[tauri::command]
pub async fn delete_fallback_slot(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    slot_index: usize,
) -> Result<ApplySlotOutcome, String> {
    let paths = state.paths.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        delete_fallback_slot_with_live_policy(
            &paths.conf_path,
            &paths.backups_dir,
            &expected_sha,
            slot_index,
            None,
            Some(&paths.security_reports_dir),
            true,
            |api_base, model, resolved_key| {
                lookup_failover_cached_audit(
                    &paths.security_reports_dir,
                    api_base,
                    model,
                    resolved_key,
                )
            },
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;
    state.invalidate_poll_meta_cache();
    Ok(res)
}

#[tauri::command]
pub async fn update_failback_policy(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    max_retries: u32,
    failback_timeout_seconds: u64,
    failback_request_count: u32,
) -> Result<ConfigSummary, String> {
    let paths = state.paths.clone();
    let live_vlm = state.latest_snapshot.read().ok().and_then(|g| {
        g.as_ref()
            .and_then(|s| s.vlm.as_ref())
            .and_then(|v| v.result.clone())
    });
    let res = tauri::async_runtime::spawn_blocking(move || {
        update_failback_policy_with_live_policy(
            &paths.conf_path,
            &paths.backups_dir,
            &expected_sha,
            max_retries,
            failback_timeout_seconds,
            failback_request_count,
            None,
            Some(&paths.security_reports_dir),
            live_vlm.as_ref(),
            true,
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;
    state.invalidate_poll_meta_cache();
    Ok(res)
}

#[tauri::command]
pub async fn copy_slot_to_reserve(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    slot_index: usize,
    note: Option<String>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (cfg, _, _) = load_raw_config(&paths.conf_path).map_err(|e| e.to_string())?;
            let (model, api_base, raw_key, _) =
                resolve_slot_raw_credential(&cfg, slot_index, None).map_err(|e| e.to_string())?;
            let default_note = format!("Slot #{}", slot_index);
            let effective_note = note
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&default_note);
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            upsert_slot_credential_into_reserve(
                &mut st,
                &model,
                &api_base,
                &raw_key,
                effective_note,
                None,
            )
            .map_err(|e| e.to_string())?;
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[tauri::command]
pub async fn copy_slot_to_watch(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    slot_index: usize,
    alias: Option<String>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (cfg, _, _) = load_raw_config(&paths.conf_path).map_err(|e| e.to_string())?;
            let (model, api_base, raw_key, _) =
                resolve_slot_raw_credential(&cfg, slot_index, None).map_err(|e| e.to_string())?;
            let default_alias = format!("Slot #{}", slot_index);
            let effective_alias = alias
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&default_alias);
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            upsert_slot_credential_into_watchlist(
                &mut st,
                &model,
                &api_base,
                &raw_key,
                effective_alias,
                None,
            )
            .map_err(|e| e.to_string())?;
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[tauri::command]
pub async fn read_monitor_state(
    state: State<'_, Arc<CockpitState>>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (st, sha) = load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
        Ok(build_monitor_summary(&paths, &st, &sha))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[tauri::command]
pub async fn upsert_watch_entry(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    mut input: UpsertWatchInput,
    inherit_source: Option<CredentialSource>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            if input.api_key.as_deref().is_none_or(|k| k.trim().is_empty()) {
                if let Some(inherited) = resolve_inherited_key_for_endpoint(
                    &paths,
                    inherit_source.as_ref(),
                    &input.api_base,
                )? {
                    input.api_key = Some(inherited);
                }
            }
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            upsert_watch_record(&mut st, &input).map_err(|e| e.to_string())?;
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorPrefsPatch {
    #[serde(default, alias = "run_with_windows")]
    pub run_with_windows: Option<bool>,
    #[serde(default, alias = "master_enabled")]
    pub master_enabled: Option<bool>,
    #[serde(default, alias = "watch_interval_minutes")]
    pub watch_interval_minutes: Option<u32>,
    #[serde(default, alias = "notify_on_down")]
    pub notify_on_down: Option<bool>,
    #[serde(default, alias = "notify_on_failover")]
    pub notify_on_failover: Option<bool>,
    #[serde(default, alias = "watch_id")]
    pub watch_id: Option<String>,
    #[serde(default, alias = "row_enabled")]
    pub row_enabled: Option<bool>,
}

#[tauri::command]
pub async fn set_watch_auto_state(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    patch: MonitorPrefsPatch,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            if let Some(startup) = patch.run_with_windows {
                sync_windows_startup_shortcut(startup, &paths.ov_home)?;
                st.run_with_windows = startup;
            }
            if let Some(m) = patch.master_enabled {
                st.watch_auto_enabled = m;
            }
            if let Some(mins) = patch.watch_interval_minutes {
                if !(1..=120).contains(&mins) {
                    return Err("Watch interval must be between 1 and 120 minutes".to_string());
                }
                st.watch_interval_minutes = mins;
            }
            if let Some(nd) = patch.notify_on_down {
                st.notify_on_down = nd;
            }
            if let Some(nf) = patch.notify_on_failover {
                st.notify_on_failover = nf;
            }
            if let (Some(wid), Some(ren)) = (patch.watch_id, patch.row_enabled) {
                set_watch_row_auto(&mut st, &wid, ren).map_err(|e| e.to_string())?;
            }
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[tauri::command]
pub async fn delete_watch_entry(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    watch_id: String,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let (summary, changed) = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            let before_len = st.watch_keys.len();
            st.watch_keys.retain(|w| w.id != watch_id);
            if st.watch_keys.len() == before_len {
                return Ok::<(MonitorStateSummary, bool), String>((
                    build_monitor_summary(&paths, &st, &cur_sha),
                    false,
                ));
            }
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok((build_monitor_summary(&paths, &st, &new_sha), true))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    if changed {
        state.invalidate_poll_meta_cache();
        let _ = app.emit("monitor://updated", &summary);
    }
    Ok(summary)
}

#[tauri::command]
pub async fn upsert_reserve_entry(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    expected_reserves_sha: String,
    mut input: UpsertReserveInput,
    inherit_source: Option<CredentialSource>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            if input.api_key.as_deref().is_none_or(|k| k.trim().is_empty()) {
                if let Some(inherited) = resolve_inherited_key_for_endpoint(
                    &paths,
                    inherit_source.as_ref(),
                    &input.api_base,
                )? {
                    input.api_key = Some(inherited);
                }
            }
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            verify_reserves_sha(&st.spare_models, &expected_reserves_sha)
                .map_err(|e| e.to_string())?;
            upsert_reserve_record(&mut st, &input).map_err(|e| e.to_string())?;
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[tauri::command]
pub async fn delete_reserve_entry(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    expected_reserves_sha: String,
    index: usize,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            verify_reserves_sha(&st.spare_models, &expected_reserves_sha)
                .map_err(|e| e.to_string())?;
            if index >= st.spare_models.len() {
                return Err(format!("Reserve index {} out of range", index));
            }
            st.spare_models.remove(index);
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[tauri::command]
pub async fn promote_reserve_to_slot(
    state: State<'_, Arc<CockpitState>>,
    expected_conf_sha: String,
    expected_reserves_sha: String,
    reserve_index: usize,
    slot_index: usize,
    allow_unaudited: bool,
) -> Result<ApplySlotOutcome, String> {
    let paths = state.paths.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        let (st, _) = load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
        verify_reserves_sha(&st.spare_models, &expected_reserves_sha).map_err(|e| e.to_string())?;
        let rec = st
            .spare_models
            .get(reserve_index)
            .ok_or_else(|| format!("Reserve index {} out of range", reserve_index))?;
        let resolved = resolve_secret(&rec.api_key, None);
        if resolved.status != SecretStatus::SecretReady {
            return Err(format!(
                "Reserve credential not ready ({:?})",
                resolved.status
            ));
        }
        let conf_key = if is_env_ref(rec.api_key.trim()) {
            rec.api_key.trim().to_string()
        } else {
            resolved.value
        };
        let input = SlotUpdateInput {
            slot_index,
            provider: None,
            model: rec.model.clone(),
            api_base: rec.api_base.clone(),
            api_key: Some(conf_key),
            allow_unaudited,
            manual_save: false,
        };
        apply_slot_update_with_live_policy(
            &paths.conf_path,
            &paths.backups_dir,
            &expected_conf_sha,
            &input,
            None,
            Some(&paths.security_reports_dir),
            true,
            |api_base, model, resolved_key| {
                lookup_failover_cached_audit(
                    &paths.security_reports_dir,
                    api_base,
                    model,
                    resolved_key,
                )
            },
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?;
    if res.is_ok() {
        state.invalidate_poll_meta_cache();
    }
    res
}

#[tauri::command]
pub async fn copy_reserve_to_watch(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    expected_reserves_sha: String,
    reserve_index: usize,
    alias: Option<String>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            verify_reserves_sha(&st.spare_models, &expected_reserves_sha)
                .map_err(|e| e.to_string())?;
            copy_reserve_into_watchlist(&mut st, reserve_index, alias.as_deref(), None)
                .map_err(|e| e.to_string())?;
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[tauri::command]
pub async fn copy_watch_to_reserve(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    watch_id: String,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            copy_watch_into_reserve(&mut st, &watch_id, None).map_err(|e| e.to_string())?;
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };
    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[tauri::command]
pub async fn probe_watch_entry(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    watch_id: String,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let wid_read = watch_id.clone();

    let (model, api_base, raw_key, start_rev, interval_secs) =
        tauri::async_runtime::spawn_blocking({
            let mon_path = paths.monitor_json_path.clone();
            move || -> Result<(String, String, String, u64, f64), String> {
                let (st, _) = load_monitor_state(&mon_path).map_err(|e| e.to_string())?;
                let rec = st
                    .watch_keys
                    .iter()
                    .find(|w| w.id == wid_read)
                    .ok_or_else(|| format!("Watch entry '{}' not found", wid_read))?;
                let interval = (st.watch_interval_minutes.max(1) as f64) * 60.0;
                Ok((
                    rec.model.clone(),
                    rec.api_base.clone(),
                    rec.api_key.clone(),
                    rec.rev,
                    interval,
                ))
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??;

    let outcome = probe_watch_credential(&model, &api_base, &raw_key, None).await;

    let (summary, maybe_alert, saved) = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(
            move || -> Result<(MonitorStateSummary, Option<AutoDisabledAlert>, bool), String> {
                let (mut st, cur_sha) =
                    load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
                let mut alert = None;
                if let Some(rec) = st
                    .watch_keys
                    .iter_mut()
                    .find(|w| w.id == watch_id && w.rev == start_rev)
                {
                    alert = record_watch_probe_outcome(rec, outcome, interval_secs);
                    let new_sha = save_monitor_state_with_live_policy(
                        &paths.monitor_json_path,
                        &paths.backups_dir,
                        &st,
                        &cur_sha,
                        true,
                    )
                    .map_err(|e| e.to_string())?;
                    return Ok((build_monitor_summary(&paths, &st, &new_sha), alert, true));
                }
                Ok((build_monitor_summary(&paths, &st, &cur_sha), alert, false))
            },
        )
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };

    if saved {
        state.invalidate_poll_meta_cache();
        let _ = app.emit("monitor://updated", &summary);
    }

    if let Some(alert) = maybe_alert {
        let _ = app.emit("watchlist://auto-disabled", &alert);
        tauri::async_runtime::spawn_blocking(move || {
            crate::dispatch_watch_auto_disabled_balloon(
                &alert.alias,
                &alert.model,
                alert.status_code,
            );
        });
    }

    Ok(summary)
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReserveBatchProgressEvent {
    Started {
        total: usize,
    },
    RowDone {
        completed: usize,
        total: usize,
        index: usize,
        model: String,
        outcome: ProbeOutcome,
    },
    Completed {
        cancelled: bool,
        completed: usize,
        total: usize,
    },
}

#[tauri::command]
pub async fn list_provider_models(
    state: State<'_, Arc<CockpitState>>,
    target: CredentialSource,
) -> Result<ProviderModelsResult, String> {
    let paths = state.paths.clone();
    let src =
        tauri::async_runtime::spawn_blocking(move || resolve_credential_source(&paths, &target))
            .await
            .map_err(|e| format!("spawn_blocking panicked: {}", e))??;
    Ok(fetch_provider_models(&src.api_base, &src.resolved_key).await)
}

#[tauri::command]
pub async fn probe_credential(
    state: State<'_, Arc<CockpitState>>,
    target: CredentialSource,
    model_override: Option<String>,
) -> Result<ProbeOutcome, String> {
    let paths = state.paths.clone();
    let src =
        tauri::async_runtime::spawn_blocking(move || resolve_credential_source(&paths, &target))
            .await
            .map_err(|e| format!("spawn_blocking panicked: {}", e))??;
    let model = model_override
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .or(src.default_model)
        .ok_or_else(|| "Model name is required for probe".to_string())?;
    Ok(probe_chat_model(
        &model,
        &src.api_base,
        &src.resolved_key,
        DEFAULT_PROBE_TIMEOUT_MS,
    )
    .await)
}

#[tauri::command]
pub async fn probe_reserve_entry(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    expected_reserves_sha: String,
    index: usize,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let sha_for_load = expected_reserves_sha.clone();
    let (model, api_base, raw_key) = tauri::async_runtime::spawn_blocking({
        let mon_path = paths.monitor_json_path.clone();
        move || -> Result<(String, String, String), String> {
            let (st, _) = load_monitor_state(&mon_path).map_err(|e| e.to_string())?;
            verify_reserves_sha(&st.spare_models, &sha_for_load).map_err(|e| e.to_string())?;
            let rec = st
                .spare_models
                .get(index)
                .ok_or_else(|| format!("Reserve index {} out of range", index))?;
            Ok((rec.model.clone(), rec.api_base.clone(), rec.api_key.clone()))
        }
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;

    let outcome = probe_watch_credential(&model, &api_base, &raw_key, None).await;

    let (summary, saved) = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(
            move || -> Result<(MonitorStateSummary, bool), String> {
                let (mut st, cur_sha) =
                    load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
                let target_idx = if verify_reserves_sha(&st.spare_models, &expected_reserves_sha)
                    .is_ok()
                    && index < st.spare_models.len()
                {
                    Some(index)
                } else {
                    find_reserve_fallback_index(&st.spare_models, &model, &api_base, &raw_key)
                };
                if let Some(real_idx) = target_idx {
                    set_reserve_probe_outcome(&mut st, real_idx, outcome)
                        .map_err(|e| e.to_string())?;
                    let new_sha = save_monitor_state_with_live_policy(
                        &paths.monitor_json_path,
                        &paths.backups_dir,
                        &st,
                        &cur_sha,
                        true,
                    )
                    .map_err(|e| e.to_string())?;
                    return Ok((build_monitor_summary(&paths, &st, &new_sha), true));
                }
                Ok((build_monitor_summary(&paths, &st, &cur_sha), false))
            },
        )
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };

    if saved {
        state.invalidate_poll_meta_cache();
        let _ = app.emit("monitor://updated", &summary);
    }
    Ok(summary)
}

#[tauri::command]
pub async fn probe_reserves_batch(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    expected_reserves_sha: String,
    indices: Vec<usize>,
    on_event: Channel<ReserveBatchProgressEvent>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let sha_check = expected_reserves_sha.clone();
    let picked: Vec<(usize, String, String, String)> = tauri::async_runtime::spawn_blocking({
        let mon_path = paths.monitor_json_path.clone();
        move || -> Result<Vec<(usize, String, String, String)>, String> {
            let (st, _) = load_monitor_state(&mon_path).map_err(|e| e.to_string())?;
            verify_reserves_sha(&st.spare_models, &sha_check).map_err(|e| e.to_string())?;
            let target_indices: Vec<usize> = if indices.is_empty() {
                (0..st.spare_models.len()).collect()
            } else {
                let mut seen = std::collections::HashSet::new();
                indices
                    .into_iter()
                    .filter(|&i| i < st.spare_models.len() && seen.insert(i))
                    .collect()
            };
            Ok(target_indices
                .into_iter()
                .map(|i| {
                    let r = &st.spare_models[i];
                    (i, r.model.clone(), r.api_base.clone(), r.api_key.clone())
                })
                .collect())
        }
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;

    let total = picked.len();
    let _ = on_event.send(ReserveBatchProgressEvent::Started { total });

    if total == 0 {
        let _ = on_event.send(ReserveBatchProgressEvent::Completed {
            cancelled: false,
            completed: 0,
            total: 0,
        });
        return read_monitor_state(state).await;
    }

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let cancel_check_tx = cancel_tx.clone();
    if let Ok(mut guard) = state.reserve_batch_cancel.lock() {
        if let Some(prev) = guard.replace(cancel_tx) {
            let _ = prev.send(true);
        }
    }

    let mut groups: std::collections::BTreeMap<String, Vec<(usize, String, String, String)>> =
        std::collections::BTreeMap::new();
    for item in picked {
        groups
            .entry(normalize_endpoint(&item.2))
            .or_default()
            .push(item);
    }

    let sem = Arc::new(tokio::sync::Semaphore::new(2));
    let completed_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(groups.len());

    for (_ep, items) in groups {
        let sem_ref = Arc::clone(&sem);
        let mut rx = cancel_rx.clone();
        let done_ref = Arc::clone(&completed_count);
        let ch = on_event.clone();
        handles.push(tokio::spawn(async move {
            let _permit = match tokio::select! {
                _ = rx.wait_for(|v| *v) => None,
                p = sem_ref.acquire_owned() => p.ok(),
            } {
                Some(p) => p,
                None => return Vec::new(),
            };

            let mut out = Vec::with_capacity(items.len());
            for (idx, model, api_base, raw_key) in items {
                if *rx.borrow() {
                    break;
                }
                let maybe_outcome = tokio::select! {
                    _ = rx.wait_for(|v| *v) => None,
                    res = probe_watch_credential(&model, &api_base, &raw_key, None) => Some(res),
                };
                let Some(outcome) = maybe_outcome else {
                    break;
                };
                let c = done_ref.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let _ = ch.send(ReserveBatchProgressEvent::RowDone {
                    completed: c,
                    total,
                    index: idx,
                    model: model.clone(),
                    outcome: outcome.clone(),
                });
                out.push((idx, model, api_base, raw_key, outcome));
            }
            out
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok(chunk) = h.await {
            results.extend(chunk);
        }
    }
    let was_cancelled = *cancel_rx.borrow();
    if let Ok(mut guard) = state.reserve_batch_cancel.lock() {
        if guard
            .as_ref()
            .is_some_and(|tx| tx.same_channel(&cancel_check_tx))
        {
            *guard = None;
        }
    }

    let done_final = completed_count.load(std::sync::atomic::Ordering::SeqCst);
    let _ = on_event.send(ReserveBatchProgressEvent::Completed {
        cancelled: was_cancelled,
        completed: done_final,
        total,
    });

    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || -> Result<MonitorStateSummary, String> {
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            if results.is_empty() {
                return Ok(build_monitor_summary(&paths, &st, &cur_sha));
            }
            let sha_still_matches =
                verify_reserves_sha(&st.spare_models, &expected_reserves_sha).is_ok();
            let mut changed = false;
            for (orig_idx, model, api_base, raw_key, outcome) in results {
                let target_idx = if sha_still_matches && orig_idx < st.spare_models.len() {
                    Some(orig_idx)
                } else {
                    find_reserve_fallback_index(&st.spare_models, &model, &api_base, &raw_key)
                };
                if let Some(real_idx) = target_idx {
                    if set_reserve_probe_outcome(&mut st, real_idx, outcome).is_ok() {
                        changed = true;
                    }
                }
            }
            if !changed {
                return Ok(build_monitor_summary(&paths, &st, &cur_sha));
            }
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &cur_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok(build_monitor_summary(&paths, &st, &new_sha))
        })
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))??
    };

    state.invalidate_poll_meta_cache();
    let _ = app.emit("monitor://updated", &summary);
    Ok(summary)
}

#[tauri::command]
pub async fn cancel_reserve_batch_probe(state: State<'_, Arc<CockpitState>>) -> Result<(), String> {
    if let Ok(mut guard) = state.reserve_batch_cancel.lock() {
        if let Some(tx) = guard.take() {
            let _ = tx.send(true);
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn run_provider_benchmark(
    state: State<'_, Arc<CockpitState>>,
    target: CredentialSource,
    models: Vec<String>,
    rounds: Option<usize>,
    on_event: Channel<BenchmarkProgressEvent>,
) -> Result<Vec<BenchmarkModelSummary>, String> {
    let paths = state.paths.clone();
    let src =
        tauri::async_runtime::spawn_blocking(move || resolve_credential_source(&paths, &target))
            .await
            .map_err(|e| format!("spawn_blocking panicked: {}", e))??;

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let cancel_check_tx = cancel_tx.clone();
    if let Ok(mut guard) = state.benchmark_cancel.lock() {
        if let Some(prev) = guard.replace(cancel_tx) {
            let _ = prev.send(true);
        }
    }

    let (results, _) = execute_provider_benchmark(
        models,
        rounds.unwrap_or(3),
        &src.api_base,
        &src.resolved_key,
        cancel_rx,
        |ev| {
            let _ = on_event.send(ev);
        },
    )
    .await;

    if let Ok(mut guard) = state.benchmark_cancel.lock() {
        if guard
            .as_ref()
            .is_some_and(|tx| tx.same_channel(&cancel_check_tx))
        {
            *guard = None;
        }
    }
    Ok(results)
}

#[tauri::command]
pub async fn cancel_provider_benchmark(state: State<'_, Arc<CockpitState>>) -> Result<(), String> {
    if let Ok(mut guard) = state.benchmark_cancel.lock() {
        if let Some(tx) = guard.take() {
            let _ = tx.send(true);
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn read_log_tail(
    state: State<'_, Arc<CockpitState>>,
    log_name: String,
    max_lines: Option<usize>,
) -> Result<LogTailOutcome, String> {
    let ov_home = state.paths.ov_home.clone();
    let lines = max_lines.unwrap_or(300);
    tauri::async_runtime::spawn_blocking(move || read_allowed_log_tail(&ov_home, &log_name, lines))
        .await
        .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AuditTargetRequest {
    Slot {
        slot_index: usize,
    },
    Watch {
        watch_id: String,
    },
    Reserve {
        index: usize,
    },
    ProviderModel {
        target: CredentialSource,
        model: String,
    },
}

#[tauri::command]
pub async fn run_security_audit(
    state: State<'_, Arc<CockpitState>>,
    target: AuditTargetRequest,
    force_refresh: Option<bool>,
) -> Result<AuditReportDocument, String> {
    let paths = state.paths.clone();
    let bypass_cache = force_refresh.unwrap_or(false);
    let (model, api_base, resolved_key, cached_doc) = tauri::async_runtime::spawn_blocking({
        let paths = paths.clone();
        move || -> Result<(String, String, String, Option<AuditReportDocument>), String> {
            let (model, api_base, resolved_key, ttl_s) = match target {
                AuditTargetRequest::Slot { slot_index } => {
                    let (cfg, _, _) =
                        load_raw_config(&paths.conf_path).map_err(|e| e.to_string())?;
                    let (m, b, sec) = resolve_slot_audit_target(&cfg, slot_index, None)
                        .map_err(|e| e.to_string())?;
                    let ttl = if slot_index == 0 {
                        AUDIT_TTL_PRIMARY_S
                    } else {
                        AUDIT_TTL_FAILOVER_S
                    };
                    (m, b, sec.value, ttl)
                }
                AuditTargetRequest::Watch { watch_id } => {
                    let (st, _) =
                        load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
                    let rec = st
                        .watch_keys
                        .iter()
                        .find(|w| w.id == watch_id)
                        .ok_or_else(|| format!("Watch '{}' not found", watch_id))?;
                    let sec = resolve_secret(&rec.api_key, None);
                    if sec.status != SecretStatus::SecretReady {
                        return Err(format!("Watch credential not ready: {:?}", sec.status));
                    }
                    (
                        rec.model.clone(),
                        rec.api_base.clone(),
                        sec.value,
                        AUDIT_TTL_FAILOVER_S,
                    )
                }
                AuditTargetRequest::Reserve { index } => {
                    let (st, _) =
                        load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
                    let rec = st
                        .spare_models
                        .get(index)
                        .ok_or_else(|| format!("Reserve index {} out of range", index))?;
                    let sec = resolve_secret(&rec.api_key, None);
                    if sec.status != SecretStatus::SecretReady {
                        return Err(format!("Reserve credential not ready: {:?}", sec.status));
                    }
                    (
                        rec.model.clone(),
                        rec.api_base.clone(),
                        sec.value,
                        AUDIT_TTL_FAILOVER_S,
                    )
                }
                AuditTargetRequest::ProviderModel { target, model } => {
                    let clean_model = model.trim().to_string();
                    if clean_model.is_empty() {
                        return Err("Model name is required for security audit".to_string());
                    }
                    let src = resolve_credential_source(&paths, &target)?;
                    (
                        clean_model,
                        src.api_base,
                        src.resolved_key,
                        AUDIT_TTL_FAILOVER_S,
                    )
                }
            };
            let cached = if bypass_cache {
                None
            } else {
                load_cached_audit_document(
                    &paths.security_reports_dir,
                    &api_base,
                    &model,
                    &resolved_key,
                    ttl_s,
                )
            };
            Ok((model, api_base, resolved_key, cached))
        }
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;

    if let Some(doc) = cached_doc {
        return Ok(doc);
    }

    Ok(run_provider_audit(
        &paths.security_reports_dir,
        &api_base,
        &model,
        &resolved_key,
    )
    .await)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceControlOutcome {
    pub action: String,
    pub task_end_rc: Option<i32>,
    pub task_run_rc: i32,
    pub terminated_pids: Vec<u32>,
    pub locks_cleaned: Vec<String>,
    pub health_ok: bool,
    pub ready_ok: bool,
    pub elapsed_ms: u64,
}

#[tauri::command]
pub async fn control_openviking_service(
    state: State<'_, Arc<CockpitState>>,
    action: String,
) -> Result<ServiceControlOutcome, String> {
    let parsed_action = ServiceAction::parse(&action)?;
    let _guard = state.service_lock.lock().await;
    let started = std::time::Instant::now();
    let ov_home = state.paths.ov_home.clone();
    let port = state.server_port;

    let step = tauri::async_runtime::spawn_blocking(move || {
        execute_service_step(parsed_action, &ov_home, port)
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;

    let mut health_ok = false;
    let mut ready_ok = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(75);

    while std::time::Instant::now() < deadline {
        let (h_st, h_body, _) = state.telemetry_client.fetch_health().await;
        if h_st == EndpointStatus::Ok && h_body.as_ref().is_some_and(|h| h.healthy) {
            health_ok = true;
            let (r_st, r_body, _) = state.telemetry_client.fetch_ready().await;
            if r_st == EndpointStatus::Ok && r_body.as_ref().is_some_and(|r| r.status == "ready") {
                ready_ok = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    }

    state.invalidate_poll_meta_cache();
    let _ = collect_telemetry_once(state.inner()).await;

    Ok(ServiceControlOutcome {
        action: step.action,
        task_end_rc: step.task_end_rc,
        task_run_rc: step.task_run_rc,
        terminated_pids: step.terminated_pids,
        locks_cleaned: step.locks_cleaned,
        health_ok,
        ready_ok,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

#[tauri::command]
pub async fn open_logs_folder(state: State<'_, Arc<CockpitState>>) -> Result<String, String> {
    if is_isolated_ov_home() {
        return Err(
            "Opening Explorer is disabled under COCKPIT_OV_HOME test isolation".to_string(),
        );
    }
    let logs_dir = state.paths.ov_home.join("logs");
    tauri::async_runtime::spawn_blocking(move || {
        std::fs::create_dir_all(&logs_dir)
            .map_err(|e| format!("Failed to create logs directory: {}", e))?;
        #[cfg(windows)]
        {
            let explorer = std::env::var_os("SystemRoot")
                .map(std::path::PathBuf::from)
                .map(|r| r.join("explorer.exe"))
                .filter(|p| p.is_file())
                .unwrap_or_else(|| std::path::PathBuf::from("explorer.exe"));
            std::process::Command::new(explorer)
                .arg(&logs_dir)
                .spawn()
                .map_err(|e| format!("Failed to open Explorer: {}", e))?;
        }
        Ok(display_clean_path(&logs_dir))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryOverviewPayload {
    pub memories: Option<MemoriesStatsResponse>,
    pub memories_status: EndpointStatus,
    pub vikingdb: Option<VikingDbResponse>,
    pub vikingdb_status: EndpointStatus,
    pub retrieval: Option<RetrievalObserverResponse>,
    pub retrieval_status: EndpointStatus,
    pub storage: StorageFootprint,
}

#[tauri::command]
pub async fn get_memory_overview(
    state: State<'_, Arc<CockpitState>>,
) -> Result<MemoryOverviewPayload, String> {
    let _ = read_cached_poll_meta(state.inner()).await;
    let ov_home = state.paths.ov_home.clone();
    let storage_fut =
        tauri::async_runtime::spawn_blocking(move || inspect_storage_footprint(&ov_home));

    let ((mem_st, mem_body, _), (vdb_st, vdb_body, _), (ret_st, ret_body, _), storage_res) = tokio::join!(
        state.telemetry_client.fetch_memories(),
        state.telemetry_client.fetch_vikingdb(),
        state.telemetry_client.fetch_retrieval_observer(),
        storage_fut,
    );

    let storage = storage_res.map_err(|e| format!("spawn_blocking panicked: {}", e))?;
    Ok(MemoryOverviewPayload {
        memories: mem_body,
        memories_status: mem_st,
        vikingdb: vdb_body,
        vikingdb_status: vdb_st,
        retrieval: ret_body,
        retrieval_status: ret_st,
        storage,
    })
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchMemoriesInput {
    pub query: String,
    #[serde(default, alias = "target_uri")]
    pub target_uri: Option<String>,
    #[serde(default, alias = "context_type")]
    pub context_type: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SanitizedSearchHit {
    pub context_type: String,
    pub uri: String,
    pub level: Option<i32>,
    pub score: Option<f64>,
    pub abstract_text: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchMemoriesOutcome {
    pub hits: Vec<SanitizedSearchHit>,
    pub total: usize,
    pub latency_ms: u64,
}

#[tauri::command]
pub async fn search_memories(
    state: State<'_, Arc<CockpitState>>,
    input: SearchMemoriesInput,
) -> Result<SearchMemoriesOutcome, String> {
    let clean_query = input.query.trim().to_string();
    if clean_query.is_empty() {
        return Err("Vui lòng nhập từ khóa hoặc câu hỏi cần tra cứu.".to_string());
    }
    let target_uri = input
        .target_uri
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let context_type = input
        .context_type
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let limit = input.limit.unwrap_or(10).clamp(1, 50);

    let _ = read_cached_poll_meta(state.inner()).await;
    let req = SearchFindRequest {
        query: clean_query,
        target_uri,
        context_type,
        limit,
    };
    let (res, latency_ms) = state.telemetry_client.search_find(&req).await?;

    let mut raw_hits: Vec<SearchFindHit> = Vec::new();
    raw_hits.extend(res.memories);
    raw_hits.extend(res.resources);
    raw_hits.extend(res.skills);
    raw_hits.sort_by(|a, b| {
        let sa = a.score.unwrap_or(0.0);
        let sb = b.score.unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    let hits: Vec<SanitizedSearchHit> = raw_hits
        .into_iter()
        .take(limit)
        .map(|h| SanitizedSearchHit {
            context_type: presentation_sanitize_text(&h.context_type, None),
            uri: presentation_sanitize_text(&h.uri, None),
            level: h.level,
            score: h.score,
            abstract_text: presentation_sanitize_text(
                h.abstract_text.as_deref().unwrap_or(""),
                None,
            ),
        })
        .collect();
    let total = res.total.unwrap_or(hits.len());

    Ok(SearchMemoriesOutcome {
        hits,
        total,
        latency_ms,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VikingContentOutcome {
    pub uri: String,
    pub content: String,
}

#[tauri::command]
pub async fn read_viking_content(
    state: State<'_, Arc<CockpitState>>,
    uri: String,
) -> Result<VikingContentOutcome, String> {
    let _ = read_cached_poll_meta(state.inner()).await;
    let raw = state.telemetry_client.read_content(&uri, 16_384).await?;
    Ok(VikingContentOutcome {
        uri: presentation_sanitize_text(&uri, None),
        content: presentation_sanitize_text(&raw, None),
    })
}
