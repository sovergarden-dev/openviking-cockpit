//! Tauri V2 application bootstrap, system tray setup, and background telemetry & watchlist workers.

pub mod commands;
pub mod state;

use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Position, RunEvent, Size,
    WebviewWindow, Window, WindowEvent,
};

use cockpit_rs::services::watchlist::{
    format_window_geometry, load_monitor_state, parse_window_geometry,
    save_monitor_state_with_live_policy,
};

use crate::commands::{collect_telemetry_once, run_due_watch_auto_pass};
use crate::state::{CockpitPaths, CockpitState};

/// Emits a native Win32 tray balloon (`Shell_NotifyIconW` `NIF_INFO`) without raw credentials (`COCKPIT_RUST_SPEC` §4.3).
#[cfg(windows)]
pub fn dispatch_tray_balloon(title: &str, body: &str) -> bool {
    use std::mem::{size_of, zeroed};
    use std::ptr::null;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_INFO, NIIF_WARNING, NIM_MODIFY, NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowExW, GetWindowThreadProcessId};

    fn copy_wide_bounded(src: &str, dst: &mut [u16]) {
        if dst.is_empty() {
            return;
        }
        let cap = dst.len() - 1;
        let mut idx = 0;
        for ch in src.chars() {
            let mut buf = [0u16; 2];
            let units = ch.encode_utf16(&mut buf);
            if idx + units.len() > cap {
                break;
            }
            for &u in units.iter() {
                dst[idx] = u;
                idx += 1;
            }
        }
        dst[idx] = 0;
    }

    let class_name: Vec<u16> = "tray_icon_app\0".encode_utf16().collect();
    let self_pid = unsafe { GetCurrentProcessId() };

    unsafe {
        let mut prev_hwnd = std::ptr::null_mut();
        loop {
            let hwnd = FindWindowExW(std::ptr::null_mut(), prev_hwnd, class_name.as_ptr(), null());
            if hwnd.is_null() {
                break;
            }
            let mut owner_pid = 0u32;
            GetWindowThreadProcessId(hwnd, &mut owner_pid);
            if owner_pid == self_pid {
                for uid in [1u32, 0u32, 2u32] {
                    let mut nid: NOTIFYICONDATAW = zeroed();
                    nid.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
                    nid.hWnd = hwnd;
                    nid.uID = uid;
                    nid.uFlags = NIF_INFO;
                    nid.dwInfoFlags = NIIF_WARNING;
                    copy_wide_bounded(title, &mut nid.szInfoTitle);
                    copy_wide_bounded(body, &mut nid.szInfo);
                    if Shell_NotifyIconW(NIM_MODIFY, &nid) != 0 {
                        return true;
                    }
                }
            }
            prev_hwnd = hwnd;
        }
    }
    false
}

#[cfg(not(windows))]
pub fn dispatch_tray_balloon(_title: &str, _body: &str) -> bool {
    false
}

pub fn dispatch_watch_auto_disabled_balloon(alias: &str, model: &str, status_code: u16) {
    let clean_alias = if alias.trim().is_empty() {
        "Key theo dõi"
    } else {
        alias.trim()
    };
    let body = format!(
        "Key '{}' ({}) đã tự tắt Auto do lỗi HTTP {} liên tiếp 2 lần.",
        clean_alias,
        model.trim(),
        status_code
    );
    let _ = dispatch_tray_balloon("THEO DÕI: Key bị tắt Auto", &body);
}

fn capture_window_geometry_draft(window: &Window) {
    if window.label() != "main" || window.is_minimized().unwrap_or(false) {
        return;
    }
    let scale = window.scale_factor().unwrap_or(1.0);
    let Ok(phys_size) = window.inner_size() else {
        return;
    };
    let logical_size: LogicalSize<u32> = phys_size.to_logical(scale);
    let logical_pos = window
        .outer_position()
        .ok()
        .map(|p| p.to_logical::<i32>(scale));
    let Some(geo) = format_window_geometry(
        logical_size.width,
        logical_size.height,
        logical_pos.map(|p| p.x),
        logical_pos.map(|p| p.y),
    ) else {
        return;
    };
    if let Some(st) = window
        .app_handle()
        .try_state::<std::sync::Arc<CockpitState>>()
    {
        if let Ok(mut pending) = st.pending_geometry.lock() {
            *pending = Some(geo);
        }
    }
}

fn restore_saved_window_geometry(win: &WebviewWindow, mon_path: &std::path::Path) {
    let Ok((mon_state, _)) = load_monitor_state(mon_path) else {
        return;
    };
    let Some(geo) = parse_window_geometry(&mon_state.geometry) else {
        return;
    };
    let _ = win.set_size(Size::Logical(LogicalSize::new(
        geo.width as f64,
        geo.height as f64,
    )));
    let (Some(lx), Some(ly)) = (geo.x, geo.y) else {
        return;
    };
    let scale = win.scale_factor().unwrap_or(1.0);
    let px = ((lx as f64) * scale).round() as i32;
    let py = ((ly as f64) * scale).round() as i32;
    let visible_on_any_monitor = win
        .available_monitors()
        .ok()
        .filter(|m| !m.is_empty())
        .map(|monitors| {
            monitors.iter().any(|m| {
                let mpos = m.position();
                let msize = m.size();
                let mx2 = mpos.x.saturating_add(msize.width as i32);
                let my2 = mpos.y.saturating_add(msize.height as i32);
                px + 120 > mpos.x && px < mx2 - 80 && py + 80 > mpos.y && py < my2 - 80
            })
        })
        .unwrap_or(true);
    if visible_on_any_monitor {
        let _ = win.set_position(Position::Logical(LogicalPosition::new(
            lx as f64, ly as f64,
        )));
    } else {
        let _ = win.center();
    }
}

fn persist_geometry_on_shutdown(st: &CockpitState) {
    let maybe_geo = st.pending_geometry.lock().ok().and_then(|mut g| g.take());
    let Some(new_geo) = maybe_geo else {
        return;
    };
    if !st.paths.monitor_json_path.is_file() {
        return;
    }
    let Ok(_guard) = st.monitor_lock.try_lock() else {
        return;
    };
    let Ok((mut mon_state, cur_sha)) = load_monitor_state(&st.paths.monitor_json_path) else {
        return;
    };
    if mon_state.geometry == new_geo {
        return;
    }
    mon_state.geometry = new_geo;
    let _ = save_monitor_state_with_live_policy(
        &st.paths.monitor_json_path,
        &st.paths.backups_dir,
        &mon_state,
        &cur_sha,
        true,
    );
}

fn quit_application(app: &AppHandle) {
    if let Some(st) = app.try_state::<std::sync::Arc<CockpitState>>() {
        let _ = st.shutdown_tx.send(true);
        st.signal_background_cancellations();
        persist_geometry_on_shutdown(&st);
    }
    let _ = app.remove_tray_by_id("main-tray");
    app.exit(0);
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let show_item = MenuItem::with_id(app, "show", "Mở OpenViking Cockpit", true, None::<&str>)?;
    let test_item = MenuItem::with_id(
        app,
        "test_balloon",
        "Thử thông báo khay",
        true,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(app, "quit", "Thoát", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show_item, &test_item, &quit_item])?;

    let mut builder = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        .tooltip("OpenViking Cockpit")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }
            "test_balloon" => {
                tauri::async_runtime::spawn_blocking(|| {
                    let _ = dispatch_tray_balloon(
                        "OpenViking Cockpit",
                        "Thông báo khay hệ thống hoạt động bình thường trên Windows.",
                    );
                });
            }
            "quit" => {
                quit_application(app);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                if let Some(win) = tray.app_handle().get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }
        });

    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }

    let _ = builder.build(app)?;
    Ok(())
}

pub fn run() {
    let paths = CockpitPaths::resolve().expect("Failed to resolve OpenViking directory paths");
    let (cockpit_state, mut shutdown_rx) = CockpitState::new(paths);
    let mut watch_shutdown_rx = shutdown_rx.clone();

    let app = tauri::Builder::default()
        .manage(cockpit_state.clone())
        .on_window_event(|window, event| match event {
            WindowEvent::Resized(_) | WindowEvent::Moved(_) => {
                capture_window_geometry_draft(window);
            }
            WindowEvent::CloseRequested { .. } => {
                quit_application(window.app_handle());
            }
            _ => {}
        })
        .setup(move |app| {
            setup_tray(app.handle())?;

            if let Some(win) = app.get_webview_window("main") {
                restore_saved_window_geometry(&win, &cockpit_state.paths.monitor_json_path);
                if std::env::args().any(|a| a == "--tray") {
                    let _ = win.hide();
                }
            }

            if std::env::args().any(|a| a == "--test-balloon") {
                let log_path = cockpit_state.paths.ov_home.join("monitor").join("app.log");
                tauri::async_runtime::spawn_blocking(move || {
                    std::thread::sleep(Duration::from_millis(600));
                    let ok = dispatch_tray_balloon(
                        "OpenViking Cockpit",
                        "Thông báo khay hệ thống hoạt động bình thường trên Windows.",
                    );
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                    {
                        use std::io::Write;
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let _ = writeln!(f, "[{}] tray_test_balloon ok={}", ts, ok);
                    }
                });
            }

            let handle = app.handle().clone();
            let worker_state = cockpit_state.clone();
            tauri::async_runtime::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(2));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let snap = collect_telemetry_once(&worker_state).await;
                            let _ = handle.emit("telemetry://snapshot", &snap);
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            });

            let watch_handle = app.handle().clone();
            let watch_state = cockpit_state.clone();
            tauri::async_runtime::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(15));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            run_due_watch_auto_pass(&watch_handle, &watch_state).await;
                        }
                        _ = watch_shutdown_rx.changed() => {
                            if *watch_shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_telemetry_status,
            commands::subscribe_telemetry_channel,
            commands::switch_active_slot,
            commands::read_config,
            commands::apply_slot,
            commands::reorder_slot,
            commands::delete_fallback_slot,
            commands::update_failback_policy,
            commands::copy_slot_to_reserve,
            commands::copy_slot_to_watch,
            commands::read_monitor_state,
            commands::upsert_watch_entry,
            commands::set_watch_auto_state,
            commands::delete_watch_entry,
            commands::upsert_reserve_entry,
            commands::delete_reserve_entry,
            commands::promote_reserve_to_slot,
            commands::copy_reserve_to_watch,
            commands::copy_watch_to_reserve,
            commands::probe_watch_entry,
            commands::probe_reserve_entry,
            commands::probe_reserves_batch,
            commands::cancel_reserve_batch_probe,
            commands::list_provider_models,
            commands::probe_credential,
            commands::run_provider_benchmark,
            commands::cancel_provider_benchmark,
            commands::run_security_audit,
            commands::control_openviking_service,
            commands::open_logs_folder,
            commands::read_log_tail,
            commands::get_memory_overview,
            commands::search_memories,
            commands::read_viking_content,
        ])
        .build(tauri::generate_context!())
        .expect("error while building OpenViking Cockpit Tauri application");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            if let Some(st) = app_handle.try_state::<std::sync::Arc<CockpitState>>() {
                let _ = st.shutdown_tx.send(true);
            }
        }
    });
}
