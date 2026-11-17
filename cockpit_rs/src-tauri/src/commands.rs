//! Tauri V2 IPC command handlers.
//! Every blocking disk/DPAPI/lock operation runs inside `spawn_blocking` (`tauri.A1`).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, State};

use cockpit_rs::config::conf_gate::{
    apply_slot_update, load_raw_config, summarize_config, summarize_slots, ApplySlotOutcome,
    ConfigSummary, SlotSummary, SlotUpdateInput, AUDIT_TTL_FAILOVER_S,
};
use cockpit_rs::services::auditor_cache::load_cached_audit_verdict;
use cockpit_rs::services::telemetry::{TelemetrySnapshot, VlmActiveResponse};
use cockpit_rs::services::watchlist::{
    load_monitor_state, probe_watch_credential, record_watch_probe_outcome, save_monitor_state,
    set_watch_row_auto, summarize_monitor_state, upsert_reserve_record, upsert_watch_record,
    AutoDisabledAlert, MonitorStateSummary, UpsertReserveInput, UpsertWatchInput,
};

use crate::state::CockpitState;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SlotListResponse {
    pub conf_sha256: String,
    pub slots: Vec<SlotSummary>,
}

pub async fn collect_telemetry_once(state: &Arc<CockpitState>) -> TelemetrySnapshot {
    let conf_path = state.paths.conf_path.clone();
    let expected_emb = tauri::async_runtime::spawn_blocking(move || {
        load_raw_config(&conf_path).ok().and_then(|(cfg, _, _)| {
            cfg.embedding
                .as_ref()
                .and_then(|e| e.get("dense").or(Some(e)))
                .and_then(|d| d.get("model"))
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
        })
    })
    .await
    .ok()
    .flatten();

    let snapshot = state
        .telemetry_client
        .fetch_snapshot_with_embedding(expected_emb.as_deref())
        .await;
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
        let maybe_alert =
            tauri::async_runtime::spawn_blocking(move || -> Option<AutoDisabledAlert> {
                let (mut st, cur_sha) = load_monitor_state(&paths.monitor_json_path).ok()?;
                if !st.watch_auto_enabled {
                    return None;
                }
                let rec = st
                    .watch_keys
                    .iter_mut()
                    .find(|w| w.id == wid && w.rev == start_rev && w.auto_enabled)?;
                let alert = record_watch_probe_outcome(rec, outcome, interval_secs);
                let _ =
                    save_monitor_state(&paths.monitor_json_path, &paths.backups_dir, &st, &cur_sha);
                alert
            })
            .await
            .ok()
            .flatten();

        if let Some(alert) = maybe_alert {
            let _ = app.emit("watchlist://auto-disabled", &alert);
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
    tauri::async_runtime::spawn_blocking(move || {
        apply_slot_update(
            &paths.conf_path,
            &paths.backups_dir,
            &expected_sha,
            &input,
            None,
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
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
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
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    input: UpsertWatchInput,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (mut st, _) =
            load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
        upsert_watch_record(&mut st, &input).map_err(|e| e.to_string())?;
        let new_sha = save_monitor_state(
            &paths.monitor_json_path,
            &paths.backups_dir,
            &st,
            &expected_sha,
        )
        .map_err(|e| e.to_string())?;
        Ok(summarize_monitor_state(&st, &new_sha, None))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[tauri::command]
pub async fn set_watch_auto_state(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    master_enabled: Option<bool>,
    watch_id: Option<String>,
    row_enabled: Option<bool>,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (mut st, _) =
            load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
        if let Some(m) = master_enabled {
            st.watch_auto_enabled = m;
        }
        if let (Some(wid), Some(ren)) = (watch_id, row_enabled) {
            set_watch_row_auto(&mut st, &wid, ren).map_err(|e| e.to_string())?;
        }
        let new_sha = save_monitor_state(
            &paths.monitor_json_path,
            &paths.backups_dir,
            &st,
            &expected_sha,
        )
        .map_err(|e| e.to_string())?;
        Ok(summarize_monitor_state(&st, &new_sha, None))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[tauri::command]
pub async fn delete_watch_entry(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    watch_id: String,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (mut st, _) =
            load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
        let before_len = st.watch_keys.len();
        st.watch_keys.retain(|w| w.id != watch_id);
        if st.watch_keys.len() == before_len {
            return Err(format!("Watch entry '{}' not found", watch_id));
        }
        let new_sha = save_monitor_state(
            &paths.monitor_json_path,
            &paths.backups_dir,
            &st,
            &expected_sha,
        )
        .map_err(|e| e.to_string())?;
        Ok(summarize_monitor_state(&st, &new_sha, None))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[tauri::command]
pub async fn upsert_reserve_entry(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    input: UpsertReserveInput,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (mut st, _) =
            load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
        upsert_reserve_record(&mut st, &input).map_err(|e| e.to_string())?;
        let new_sha = save_monitor_state(
            &paths.monitor_json_path,
            &paths.backups_dir,
            &st,
            &expected_sha,
        )
        .map_err(|e| e.to_string())?;
        Ok(summarize_monitor_state(&st, &new_sha, None))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
}

#[tauri::command]
pub async fn delete_reserve_entry(
    state: State<'_, Arc<CockpitState>>,
    expected_sha: String,
    index: usize,
) -> Result<MonitorStateSummary, String> {
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (mut st, _) =
            load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
        if index >= st.spare_models.len() {
            return Err(format!("Reserve index {} out of range", index));
        }
        st.spare_models.remove(index);
        let new_sha = save_monitor_state(
            &paths.monitor_json_path,
            &paths.backups_dir,
            &st,
            &expected_sha,
        )
        .map_err(|e| e.to_string())?;
        Ok(summarize_monitor_state(&st, &new_sha, None))
    })
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))?
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

    let (summary, maybe_alert) = tauri::async_runtime::spawn_blocking(
        move || -> Result<(MonitorStateSummary, Option<AutoDisabledAlert>), String> {
            let (mut st, cur_sha) =
                load_monitor_state(&paths.monitor_json_path).map_err(|e| e.to_string())?;
            let mut alert = None;
            if let Some(rec) = st
                .watch_keys
                .iter_mut()
                .find(|w| w.id == watch_id && w.rev == start_rev)
            {
                alert = record_watch_probe_outcome(rec, outcome, interval_secs);
                let new_sha =
                    save_monitor_state(&paths.monitor_json_path, &paths.backups_dir, &st, &cur_sha)
                        .map_err(|e| e.to_string())?;
                return Ok((summarize_monitor_state(&st, &new_sha, None), alert));
            }
            Ok((summarize_monitor_state(&st, &cur_sha, None), alert))
        },
    )
    .await
    .map_err(|e| format!("spawn_blocking panicked: {}", e))??;

    if let Some(alert) = maybe_alert {
        let _ = app.emit("watchlist://auto-disabled", &alert);
    }

    Ok(summary)
}
