//! Tauri V2 application bootstrap, system tray setup, and background telemetry & watchlist workers.

pub mod commands;
pub mod state;

use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent};

use crate::commands::{collect_telemetry_once, run_due_watch_auto_pass};
use crate::state::{CockpitPaths, CockpitState};

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let show_item = MenuItem::with_id(app, "show", "Mở OpenViking Cockpit", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Thoát", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

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
        .setup(move |app| {
            setup_tray(app.handle())?;

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
