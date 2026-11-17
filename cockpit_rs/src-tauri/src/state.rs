//! Managed runtime state and filesystem path resolution for OpenViking Cockpit.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tauri::ipc::Channel;
use tokio::sync::watch;

use cockpit_rs::services::telemetry::{TelemetryClient, TelemetrySnapshot};

#[derive(Debug, Clone)]
pub struct CockpitPaths {
    pub ov_home: PathBuf,
    pub conf_path: PathBuf,
    pub backups_dir: PathBuf,
    pub monitor_json_path: PathBuf,
    pub security_reports_dir: PathBuf,
}

impl CockpitPaths {
    pub fn resolve() -> Result<Self, String> {
        let ov_home = if let Some(custom) = std::env::var_os("COCKPIT_OV_HOME") {
            PathBuf::from(custom)
        } else {
            let home = std::env::var_os("USERPROFILE")
                .or_else(|| std::env::var_os("HOME"))
                .ok_or_else(|| "Unable to resolve USERPROFILE or HOME directory".to_string())?;
            PathBuf::from(home).join(".openviking")
        };

        Ok(Self {
            conf_path: ov_home.join("ov.conf"),
            backups_dir: ov_home.join("backups"),
            monitor_json_path: ov_home.join("monitor").join("monitor.json"),
            security_reports_dir: ov_home.join("monitor").join("security_reports"),
            ov_home,
        })
    }
}

pub struct CockpitState {
    pub paths: CockpitPaths,
    pub telemetry_client: TelemetryClient,
    pub latest_snapshot: RwLock<Option<TelemetrySnapshot>>,
    pub subscribers: Mutex<Vec<Channel<TelemetrySnapshot>>>,
    pub shutdown_tx: watch::Sender<bool>,
}

impl CockpitState {
    pub fn new(paths: CockpitPaths) -> (Arc<Self>, watch::Receiver<bool>) {
        let server_url = std::env::var("COCKPIT_SERVER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:19330".to_string());
        let ollama_url = std::env::var("COCKPIT_OLLAMA_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:21434".to_string());

        let telemetry_client = TelemetryClient::new(&server_url).with_ollama_base_url(&ollama_url);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let state = Arc::new(Self {
            paths,
            telemetry_client,
            latest_snapshot: RwLock::new(None),
            subscribers: Mutex::new(Vec::new()),
            shutdown_tx,
        });
        (state, shutdown_rx)
    }

    pub fn broadcast_snapshot(&self, snapshot: &TelemetrySnapshot) {
        if let Ok(mut guard) = self.latest_snapshot.write() {
            *guard = Some(snapshot.clone());
        }
        if let Ok(mut subs) = self.subscribers.lock() {
            subs.retain(|ch| ch.send(snapshot.clone()).is_ok());
        }
    }
}
