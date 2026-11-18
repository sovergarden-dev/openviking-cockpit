//! Managed runtime state and filesystem path resolution for OpenViking Cockpit.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tauri::ipc::Channel;
use tokio::sync::watch;

use cockpit_rs::services::telemetry::{
    IncidentTracker, LifecycleSummary, TelemetryClient, TelemetrySnapshot,
};

#[derive(Debug, Clone)]
pub struct TelemetryPollMetaCache {
    pub conf_stamp: Option<(SystemTime, u64)>,
    pub expected_embedding_model: Option<String>,
    pub monitor_stamp: Option<(SystemTime, u64)>,
    pub notify_on_down: bool,
    pub notify_on_failover: bool,
    pub lifecycle_stamp: Option<(SystemTime, u64)>,
    pub lifecycle_summary: Option<LifecycleSummary>,
}

impl Default for TelemetryPollMetaCache {
    fn default() -> Self {
        Self {
            conf_stamp: None,
            expected_embedding_model: None,
            monitor_stamp: None,
            notify_on_down: true,
            notify_on_failover: true,
            lifecycle_stamp: None,
            lifecycle_summary: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CockpitPaths {
    pub ov_home: PathBuf,
    pub conf_path: PathBuf,
    pub backups_dir: PathBuf,
    pub monitor_json_path: PathBuf,
    pub security_reports_dir: PathBuf,
    pub lifecycle_log_path: PathBuf,
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
            lifecycle_log_path: ov_home.join("logs").join("lifecycle.jsonl"),
            ov_home,
        })
    }
}

pub struct CockpitState {
    pub paths: CockpitPaths,
    pub server_port: u16,
    pub telemetry_client: TelemetryClient,
    pub latest_snapshot: RwLock<Option<TelemetrySnapshot>>,
    pub incident_tracker: Mutex<IncidentTracker>,
    pub poll_meta_cache: Mutex<TelemetryPollMetaCache>,
    pub monitor_lock: tokio::sync::Mutex<()>,
    pub service_lock: tokio::sync::Mutex<()>,
    pub pending_geometry: Mutex<Option<String>>,
    pub subscribers: Mutex<Vec<Channel<TelemetrySnapshot>>>,
    pub shutdown_tx: watch::Sender<bool>,
}

fn extract_port_from_url(url: &str, default_port: u16) -> u16 {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    host_port
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(default_port)
}

impl CockpitState {
    pub fn new(paths: CockpitPaths) -> (Arc<Self>, watch::Receiver<bool>) {
        let server_url = std::env::var("COCKPIT_SERVER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:19330".to_string());
        let ollama_url = std::env::var("COCKPIT_OLLAMA_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:21434".to_string());
        let server_port = extract_port_from_url(&server_url, 19330);

        let initial_api_key = if paths.conf_path.is_file() {
            cockpit_rs::config::conf_gate::load_raw_config(&paths.conf_path)
                .ok()
                .and_then(|(cfg, _, _)| {
                    cockpit_rs::config::conf_gate::resolve_server_root_api_key(&cfg, None)
                })
        } else {
            None
        };
        let telemetry_client = TelemetryClient::new(&server_url)
            .with_ollama_base_url(&ollama_url)
            .with_api_key(initial_api_key);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let state = Arc::new(Self {
            paths,
            server_port,
            telemetry_client,
            latest_snapshot: RwLock::new(None),
            incident_tracker: Mutex::new(IncidentTracker::default()),
            poll_meta_cache: Mutex::new(TelemetryPollMetaCache::default()),
            monitor_lock: tokio::sync::Mutex::new(()),
            service_lock: tokio::sync::Mutex::new(()),
            pending_geometry: Mutex::new(None),
            subscribers: Mutex::new(Vec::new()),
            shutdown_tx,
        });
        (state, shutdown_rx)
    }

    pub fn invalidate_poll_meta_cache(&self) {
        if let Ok(mut guard) = self.poll_meta_cache.lock() {
            guard.conf_stamp = None;
            guard.monitor_stamp = None;
        }
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
