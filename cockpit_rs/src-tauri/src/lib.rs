//! Tauri V2 application bootstrap, system tray setup, and background telemetry & watchlist workers.

pub mod commands;
pub mod state;

use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};

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

    let mut builder = TrayIconBuilder::new()
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
                app.exit(0);
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
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(move |app| {
            setup_tray(app.handle())?;

            if std::env::args().any(|a| a == "--tray") {
                if let Some(win) = app.get_webview_window("main") {
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
            commands::list_slots,
            commands::apply_slot,
            commands::read_monitor_state,
            commands::upsert_watch_entry,
            commands::set_watch_auto_state,
            commands::delete_watch_entry,
            commands::upsert_reserve_entry,
            commands::delete_reserve_entry,
            commands::promote_reserve_to_slot,
            commands::copy_reserve_to_watch,
            commands::probe_watch_entry,
            commands::run_security_audit,
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
