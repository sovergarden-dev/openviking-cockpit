//! Tauri V2 IPC command handlers.
//! Every blocking disk/DPAPI/lock operation runs inside `spawn_blocking` (`tauri.A1`).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, State};

use cockpit_rs::config::conf_gate::{
    apply_slot_update_with_live_policy, load_raw_config, resolve_slot_audit_target,
    summarize_config, summarize_slots, ApplySlotOutcome, ConfigSummary, SlotSummary,
    SlotUpdateInput, AUDIT_TTL_FAILOVER_S,
};
use cockpit_rs::secrets::secret_store::{is_env_ref, resolve_secret, SecretStatus};
use cockpit_rs::services::auditor::{run_provider_audit, AuditReportDocument};
use cockpit_rs::services::auditor_cache::load_cached_audit_verdict;
use cockpit_rs::services::telemetry::{
    evaluate_telemetry_incidents, TelemetrySnapshot, VlmActiveResponse,
};
use cockpit_rs::services::watchlist::{
    copy_reserve_into_watchlist, load_monitor_state, probe_watch_credential,
    record_watch_probe_outcome, save_monitor_state_with_live_policy, set_watch_row_auto,
    summarize_monitor_state, upsert_reserve_record, upsert_watch_record, AutoDisabledAlert,
    MonitorStateSummary, UpsertReserveInput, UpsertWatchInput,
};

use crate::state::CockpitState;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SlotListResponse {
    pub conf_sha256: String,
    pub slots: Vec<SlotSummary>,
}

fn file_stamp(path: &std::path::Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    Some((modified, meta.len()))
}

async fn read_cached_poll_meta(state: &Arc<CockpitState>) -> (Option<String>, bool, bool) {
    let state_ref = Arc::clone(state);
    tauri::async_runtime::spawn_blocking(move || {
        let cur_conf_stamp = file_stamp(&state_ref.paths.conf_path);
        let cur_mon_stamp = file_stamp(&state_ref.paths.monitor_json_path);

        let prev = state_ref
            .poll_meta_cache
            .lock()
            .ok()
            .map(|g| g.clone())
            .unwrap_or_default();

        let conf_dirty = cur_conf_stamp != prev.conf_stamp;
        let mon_dirty = cur_mon_stamp != prev.monitor_stamp;
        if !conf_dirty && !mon_dirty && (cur_conf_stamp.is_some() || cur_mon_stamp.is_some()) {
            return (
                prev.expected_embedding_model,
                prev.notify_on_down,
                prev.notify_on_failover,
            );
        }

        let expected_emb = if conf_dirty {
            if cur_conf_stamp.is_some() {
                load_raw_config(&state_ref.paths.conf_path)
                    .ok()
                    .and_then(|(cfg, _, _)| {
                        cfg.embedding
                            .as_ref()
                            .and_then(|e| e.get("dense").or(Some(e)))
                            .and_then(|d| d.get("model"))
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
            } else {
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

        if let Ok(mut guard) = state_ref.poll_meta_cache.lock() {
            guard.conf_stamp = cur_conf_stamp;
            guard.expected_embedding_model = expected_emb.clone();
            guard.monitor_stamp = cur_mon_stamp;
            guard.notify_on_down = notify_on_down;
            guard.notify_on_failover = notify_on_failover;
        }

        (expected_emb, notify_on_down, notify_on_failover)
    })
    .await
    .unwrap_or((None, true, true))
}

pub async fn collect_telemetry_once(state: &Arc<CockpitState>) -> TelemetrySnapshot {
    let (expected_emb, notify_on_down, notify_on_failover) = read_cached_poll_meta(state).await;

    let snapshot = state
        .telemetry_client
        .fetch_snapshot_with_embedding(expected_emb.as_deref())
        .await;

    let alerts = state
        .incident_tracker
        .lock()
        .ok()
        .map(|mut tracker| {
            evaluate_telemetry_incidents(
                &mut tracker,
                &snapshot,
                notify_on_down,
                notify_on_failover,
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
                    let summary = summarize_monitor_state(&st, &new_sha, None);
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
    let res = state
        .telemetry_client
        .switch_active_vlm_slot(slot_index)
        .await?;
    let _ = collect_telemetry_once(state.inner()).await;
    Ok(res)
}

#[tauri::command]
pub async fn read_config(state: State<'_, Arc<CockpitState>>) -> Result<ConfigSummary, String> {
    let conf_path = state.paths.conf_path.clone();
    let live_vlm = state.latest_snapshot.read().ok().and_then(|g| {
        g.as_ref()
            .and_then(|s| s.vlm.as_ref())
            .and_then(|v| v.result.clone())
    });

    tauri::async_runtime::spawn_blocking(move || {
        let (cfg, _, sha) = load_raw_config(&conf_path).map_err(|e| e.to_string())?;
        Ok(summarize_config(
            &conf_path,
            &cfg,
            &sha,
            live_vlm.as_ref(),
            None,
        ))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[tauri::command]
pub async fn list_slots(state: State<'_, Arc<CockpitState>>) -> Result<SlotListResponse, String> {
    let conf_path = state.paths.conf_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (cfg, _, sha) = load_raw_config(&conf_path).map_err(|e| e.to_string())?;
        let slots = summarize_slots(&cfg, None);
        Ok(SlotListResponse {
            conf_sha256: sha,
            slots,
        })
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[tauri::command]
pub async fn apply_slot(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    input: SlotUpdateInput,
) -> Result<ApplySlotOutcome, String> {
    let paths = state.paths.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        apply_slot_update_with_live_policy(
            &paths.conf_path,
            &paths.backups_dir,
            &expected_sha,
            &input,
            None,
            true,
            |api_base, model, resolved_key| {
                load_cached_audit_verdict(
                    &paths.security_reports_dir,
                    api_base,
                    model,
                    resolved_key,
                    AUDIT_TTL_FAILOVER_S,
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
pub async fn read_monitor_state(
    state: State<'_, Arc<CockpitState>>,
) -> Result<MonitorStateSummary, String> {
    let mon_path = state.paths.monitor_json_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (st, sha) = load_monitor_state(&mon_path).map_err(|e| e.to_string())?;
        Ok(summarize_monitor_state(&st, &sha, None))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[tauri::command]
pub async fn upsert_watch_entry(
    app: AppHandle,
    state: State<'_, Arc<CockpitState>>,
    expected_sha: Option<String>,
    input: UpsertWatchInput,
) -> Result<MonitorStateSummary, String> {
    let _ = expected_sha;
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
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
            Ok::<MonitorStateSummary, String>(summarize_monitor_state(&st, &new_sha, None))
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
    expected_sha: Option<String>,
    patch: MonitorPrefsPatch,
) -> Result<MonitorStateSummary, String> {
    let _ = expected_sha;
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
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
            Ok::<MonitorStateSummary, String>(summarize_monitor_state(&st, &new_sha, None))
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
    expected_sha: Option<String>,
    watch_id: String,
) -> Result<MonitorStateSummary, String> {
    let _ = expected_sha;
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
                    summarize_monitor_state(&st, &cur_sha, None),
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
            Ok((summarize_monitor_state(&st, &new_sha, None), true))
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
    expected_sha: String,
    input: UpsertReserveInput,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, _) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            upsert_reserve_record(&mut st, &input).map_err(|e| e.to_string())?;
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &expected_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(summarize_monitor_state(&st, &new_sha, None))
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
    expected_sha: String,
    index: usize,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, _) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            if index >= st.spare_models.len() {
                return Err(format!("Reserve index {} out of range", index));
            }
            st.spare_models.remove(index);
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &expected_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(summarize_monitor_state(&st, &new_sha, None))
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
    reserve_index: usize,
    slot_index: usize,
    allow_unaudited: bool,
) -> Result<ApplySlotOutcome, String> {
    let paths = state.paths.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        let (st, _) = load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
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
            true,
            |api_base, model, resolved_key| {
                load_cached_audit_verdict(
                    &paths.security_reports_dir,
                    api_base,
                    model,
                    resolved_key,
                    AUDIT_TTL_FAILOVER_S,
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
    expected_sha: String,
    reserve_index: usize,
    alias: Option<String>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    let summary = {
        let _guard = state.monitor_lock.lock().await;
        tauri::async_runtime::spawn_blocking(move || {
            let (mut st, _) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            copy_reserve_into_watchlist(&mut st, reserve_index, alias.as_deref(), None)
                .map_err(|e| e.to_string())?;
            let new_sha = save_monitor_state_with_live_policy(
                &paths.monitor_json_path,
                &paths.backups_dir,
                &st,
                &expected_sha,
                true,
            )
            .map_err(|e| e.to_string())?;
            Ok::<MonitorStateSummary, String>(summarize_monitor_state(&st, &new_sha, None))
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
                    return Ok((summarize_monitor_state(&st, &new_sha, None), alert, true));
                }
                Ok((summarize_monitor_state(&st, &cur_sha, None), alert, false))
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

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AuditTargetRequest {
    Slot { slot_index: usize },
    Watch { watch_id: String },
    Reserve { index: usize },
}

#[tauri::command]
pub async fn run_security_audit(
    state: State<'_, Arc<CockpitState>>,
    target: AuditTargetRequest,
) -> Result<AuditReportDocument, String> {
    let paths = state.paths.clone();
    let (model, api_base, resolved_key) = tauri::async_runtime::spawn_blocking({
        let paths = paths.clone();
        move || -> Result<(String, String, String), String> {
            match target {
                AuditTargetRequest::Slot { slot_index } => {
                    let (cfg, _, _) =
                        load_raw_config(&paths.conf_path).map_err(|e| e.to_string())?;
                    let (m, b, sec) = resolve_slot_audit_target(&cfg, slot_index, None)
                        .map_err(|e| e.to_string())?;
                    Ok((m, b, sec.value))
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
                    Ok((rec.model.clone(), rec.api_base.clone(), sec.value))
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
                    Ok((rec.model.clone(), rec.api_base.clone(), sec.value))
                }
            }
        }
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;

    Ok(run_provider_audit(
        &paths.security_reports_dir,
        &api_base,
        &model,
        &resolved_key,
    )
    .await)
}
