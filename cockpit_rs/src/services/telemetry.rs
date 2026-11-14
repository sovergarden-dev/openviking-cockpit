//! Telemetry client and data models for OpenViking background monitoring.
//! Implements asynchronous polling for /health, /ready, /vlm/active, /vikingdb, and /stats/memories.
//! All models strictly align with JSON Schemas in docs/specs/contracts/.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Data Models (Contract Aligned, Lenient Serde)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub healthy: bool,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub auth_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadyResponse {
    pub status: String,
    pub checks: ReadyChecks,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadyChecks {
    #[serde(default)]
    pub agfs: Option<AgfsCheck>,
    #[serde(default)]
    pub vectordb: Option<String>,
    #[serde(default)]
    pub api_key_manager: Option<String>,
    #[serde(default)]
    pub embedding: Option<String>,
    #[serde(default)]
    pub ollama: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgfsCheck {
    pub status: String,
    #[serde(default)]
    pub checks: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VlmActiveResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<VlmActiveResult>,
    #[serde(default)]
    pub error: Option<Value>,
    #[serde(default)]
    pub telemetry: Option<Value>,
    #[serde(default)]
    pub profile: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VlmActiveResult {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub n: Option<usize>,
    #[serde(default)]
    pub manual_hold: Option<bool>,
    #[serde(default)]
    pub credential_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VikingDbResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<VikingDbResult>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VikingDbResult {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub is_healthy: Option<bool>,
    #[serde(default)]
    pub has_errors: Option<bool>,
    #[serde(default)]
    pub status: Option<VikingDbStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VikingDbStatus {
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub collection: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub dimension: Option<usize>,
    #[serde(default)]
    pub vector_count: Option<usize>,
    #[serde(default)]
    pub distance_metric: Option<String>,
    #[serde(default)]
    pub pure_dense_score_scale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoriesStatsResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<MemoriesStatsResult>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoriesStatsResult {
    #[serde(default)]
    pub total_memories: Option<usize>,
    #[serde(default)]
    pub by_category: Option<HashMap<String, usize>>,
    #[serde(default)]
    pub hotness_distribution: Option<HashMap<String, usize>>,
    #[serde(default)]
    pub staleness: Option<MemoriesStaleness>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoriesStaleness {
    #[serde(default)]
    pub not_accessed_7d: Option<usize>,
    #[serde(default)]
    pub not_accessed_30d: Option<usize>,
    #[serde(default)]
    pub oldest_memory_age_days: Option<f64>,
}

// ============================================================================
// Endpoint Status & Telemetry Snapshot
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointStatus {
    Ok,
    Degraded,
    HttpError(u16),
    Timeout,
    DecodeError,
    Unreachable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub timestamp_ms: u64,
    pub health: Option<HealthResponse>,
    pub health_status: EndpointStatus,
    pub health_latency_ms: u64,

    pub ready: Option<ReadyResponse>,
    pub ready_status: EndpointStatus,
    pub ready_latency_ms: u64,

    pub vlm: Option<VlmActiveResponse>,
    pub vlm_status: EndpointStatus,
    pub vlm_latency_ms: u64,

    pub vikingdb: Option<VikingDbResponse>,
    pub vikingdb_status: EndpointStatus,
    pub vikingdb_latency_ms: u64,

    pub memories: Option<MemoriesStatsResponse>,
    pub memories_status: EndpointStatus,
    pub memories_latency_ms: u64,
}

impl TelemetrySnapshot {
    pub fn is_overall_healthy(&self) -> bool {
        let health_ok = self.health_status == EndpointStatus::Ok
            && self.health.as_ref().is_some_and(|h| h.healthy);
        let ready_ok = self.ready_status == EndpointStatus::Ok
            && self.ready.as_ref().is_some_and(|r| r.status == "ready");
        health_ok && ready_ok
    }
}

// ============================================================================
// Asynchronous Telemetry Client
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("HTTP client build failure: {0}")]
    ClientBuild(#[from] reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct TelemetryClient {
    base_url: String,
    http: reqwest::Client,
}

impl Default for TelemetryClient {
    fn default() -> Self {
        Self::new("http://127.0.0.1:19330")
    }
}

impl TelemetryClient {
    pub fn try_new(base_url: &str) -> Result<Self, TelemetryError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(800))
            .connect_timeout(Duration::from_millis(300))
            .no_proxy()
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    pub fn new(base_url: &str) -> Self {
        Self::try_new(base_url).expect("Failed to build reqwest HTTP client")
    }

    async fn probe<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> (EndpointStatus, Option<T>, u64) {
        let url = format!("{}{}", self.base_url, path);
        let start = Instant::now();
        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                let latency = start.elapsed().as_millis() as u64;
                let status = if e.is_timeout() {
                    EndpointStatus::Timeout
                } else {
                    EndpointStatus::Unreachable
                };
                return (status, None, latency);
            }
        };

        let latency = start.elapsed().as_millis() as u64;
        let status_code = resp.status();
        if !status_code.is_success() {
            // Only 503 Service Unavailable with parseable structured body is classified as Degraded
            if status_code == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                if let Ok(data) = resp.json::<T>().await {
                    return (EndpointStatus::Degraded, Some(data), latency);
                }
            }
            return (
                EndpointStatus::HttpError(status_code.as_u16()),
                None,
                latency,
            );
        }

        match resp.json::<T>().await {
            Ok(data) => (EndpointStatus::Ok, Some(data), latency),
            Err(e) if e.is_timeout() => (EndpointStatus::Timeout, None, latency),
            Err(_) => (EndpointStatus::DecodeError, None, latency),
        }
    }

    pub async fn fetch_health(&self) -> (EndpointStatus, Option<HealthResponse>, u64) {
        self.probe("/health").await
    }

    pub async fn fetch_ready(&self) -> (EndpointStatus, Option<ReadyResponse>, u64) {
        self.probe("/ready").await
    }

    pub async fn fetch_vlm(&self) -> (EndpointStatus, Option<VlmActiveResponse>, u64) {
        self.probe("/api/v1/observer/vlm/active").await
    }

    pub async fn fetch_vikingdb(&self) -> (EndpointStatus, Option<VikingDbResponse>, u64) {
        self.probe("/api/v1/system/vikingdb").await
    }

    pub async fn fetch_memories(&self) -> (EndpointStatus, Option<MemoriesStatsResponse>, u64) {
        self.probe("/api/v1/system/stats/memories").await
    }

    pub async fn fetch_snapshot(&self) -> TelemetrySnapshot {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (h, r, v, db, m) = tokio::join!(
            self.fetch_health(),
            self.fetch_ready(),
            self.fetch_vlm(),
            self.fetch_vikingdb(),
            self.fetch_memories(),
        );

        TelemetrySnapshot {
            timestamp_ms: now_ms,
            health: h.1,
            health_status: h.0,
            health_latency_ms: h.2,

            ready: r.1,
            ready_status: r.0,
            ready_latency_ms: r.2,

            vlm: v.1,
            vlm_status: v.0,
            vlm_latency_ms: v.2,

            vikingdb: db.1,
            vikingdb_status: db.0,
            vikingdb_latency_ms: db.2,

            memories: m.1,
            memories_status: m.0,
            memories_latency_ms: m.2,
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn get_fixture_path(name: &str) -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .parent()
            .expect("repo root")
            .join("docs")
            .join("specs")
            .join("contracts")
            .join("fixtures")
            .join(format!("{}.json", name))
    }

    #[test]
    fn test_deserialize_contract_fixtures() {
        // 1. health.json
        let health_data = fs::read_to_string(get_fixture_path("health")).expect("read health.json");
        let health: HealthResponse = serde_json::from_str(&health_data).expect("parse health");
        assert_eq!(health.status, "ok");
        assert!(health.healthy);
        assert_eq!(health.version.as_deref(), Some("0.5.3"));

        // 2. ready.json
        let ready_data = fs::read_to_string(get_fixture_path("ready")).expect("read ready.json");
        let ready: ReadyResponse = serde_json::from_str(&ready_data).expect("parse ready");
        assert_eq!(ready.status, "ready");
        assert_eq!(ready.checks.vectordb.as_deref(), Some("ok"));

        // 3. vlm_active.json
        let vlm_data =
            fs::read_to_string(get_fixture_path("vlm_active")).expect("read vlm_active.json");
        let vlm: VlmActiveResponse = serde_json::from_str(&vlm_data).expect("parse vlm_active");
        assert_eq!(vlm.status, "ok");
        let vlm_res = vlm.result.expect("vlm result");
        assert_eq!(vlm_res.kind.as_deref(), Some("MultiCredentialVLM"));
        assert_eq!(vlm_res.index, Some(0));
        assert_eq!(vlm_res.credential_ids.expect("cred ids").len(), 4);

        // 4. vikingdb.json
        let db_data = fs::read_to_string(get_fixture_path("vikingdb")).expect("read vikingdb.json");
        let db: VikingDbResponse = serde_json::from_str(&db_data).expect("parse vikingdb");
        assert_eq!(db.status, "ok");
        let db_res = db.result.expect("db result");
        assert_eq!(db_res.status.expect("status").vector_count, Some(1000));

        // 5. memories_stats.json
        let mem_data = fs::read_to_string(get_fixture_path("memories_stats"))
            .expect("read memories_stats.json");
        let mem: MemoriesStatsResponse =
            serde_json::from_str(&mem_data).expect("parse memories_stats");
        assert_eq!(mem.status, "ok");
        let mem_res = mem.result.expect("mem result");
        assert_eq!(mem_res.total_memories, Some(1000));
    }

    #[test]
    fn test_overall_healthy_predicate() {
        let mut snapshot = TelemetrySnapshot {
            timestamp_ms: 1000,
            health: Some(HealthResponse {
                status: "ok".to_string(),
                healthy: true,
                version: Some("0.5.3".to_string()),
                auth_mode: None,
            }),
            health_status: EndpointStatus::Ok,
            health_latency_ms: 5,
            ready: Some(ReadyResponse {
                status: "ready".to_string(),
                checks: ReadyChecks {
                    agfs: None,
                    vectordb: Some("ok".to_string()),
                    api_key_manager: None,
                    embedding: Some("ok".to_string()),
                    ollama: Some("ok".to_string()),
                },
            }),
            ready_status: EndpointStatus::Ok,
            ready_latency_ms: 6,
            vlm: None,
            vlm_status: EndpointStatus::Ok,
            vlm_latency_ms: 4,
            vikingdb: None,
            vikingdb_status: EndpointStatus::Ok,
            vikingdb_latency_ms: 10,
            memories: None,
            memories_status: EndpointStatus::Ok,
            memories_latency_ms: 12,
        };

        // 1. Both health and ready are OK -> overall healthy
        assert!(snapshot.is_overall_healthy());

        // 2. Ready is degraded -> false
        snapshot.ready_status = EndpointStatus::Degraded;
        assert!(!snapshot.is_overall_healthy());

        // 3. Ready HTTP error 503 -> false
        snapshot.ready_status = EndpointStatus::HttpError(503);
        assert!(!snapshot.is_overall_healthy());

        // 4. Ready Timeout -> false
        snapshot.ready_status = EndpointStatus::Timeout;
        assert!(!snapshot.is_overall_healthy());

        // 5. Ready Unreachable -> false
        snapshot.ready_status = EndpointStatus::Unreachable;
        assert!(!snapshot.is_overall_healthy());

        // 6. Ready status not "ready" (e.g. "not_ready") -> false
        snapshot.ready_status = EndpointStatus::Ok;
        snapshot.ready.as_mut().unwrap().status = "not_ready".to_string();
        assert!(!snapshot.is_overall_healthy());

        // 7. Ready is None -> false
        snapshot.ready = None;
        assert!(!snapshot.is_overall_healthy());

        // Restore ready
        snapshot.ready = Some(ReadyResponse {
            status: "ready".to_string(),
            checks: ReadyChecks {
                agfs: None,
                vectordb: None,
                api_key_manager: None,
                embedding: None,
                ollama: None,
            },
        });

        // 8. Health healthy is false -> false
        snapshot.health.as_mut().unwrap().healthy = false;
        assert!(!snapshot.is_overall_healthy());

        // 9. Health is Degraded -> false
        snapshot.health.as_mut().unwrap().healthy = true;
        snapshot.health_status = EndpointStatus::Degraded;
        assert!(!snapshot.is_overall_healthy());

        // 10. Health is None -> false
        snapshot.health = None;
        assert!(!snapshot.is_overall_healthy());
    }

    #[tokio::test]
    async fn test_mock_http_probe_matrix() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local test port");
        let port = listener.local_addr().expect("local addr").port();
        let base_url = format!("http://127.0.0.1:{}", port);

        // Spawn mock loop responding to 4 test requests with exact Content-Length and Connection: close
        tokio::spawn(async move {
            for idx in 0..4 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;

                    let (status_line, content_type, body) = match idx {
                        // 1. 200 OK + Health JSON
                        0 => (
                            "HTTP/1.1 200 OK",
                            "application/json",
                            r#"{"status":"ok","healthy":true,"version":"0.5.3"}"#,
                        ),
                        // 2. 503 Degraded with parseable structured body
                        1 => (
                            "HTTP/1.1 503 Service Unavailable",
                            "application/json",
                            r#"{"status":"not_ready","checks":{}}"#,
                        ),
                        // 3. 500 Internal Error with plain text
                        2 => (
                            "HTTP/1.1 500 Internal Server Error",
                            "text/plain",
                            "Server Error!",
                        ),
                        // 4. 200 OK with invalid JSON
                        3 => ("HTTP/1.1 200 OK", "application/json", "{corrupted-json"),
                        _ => ("HTTP/1.1 404 Not Found", "text/plain", ""),
                    };

                    let resp = format!(
                        "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status_line,
                        content_type,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
            }
        });

        let client = TelemetryClient::new(&base_url);

        // Request 1: 200 OK
        let (status1, health, _) = client.fetch_health().await;
        assert_eq!(status1, EndpointStatus::Ok);
        assert!(health.is_some_and(|h| h.healthy));

        // Request 2: 503 Degraded
        let (status2, ready, _) = client.fetch_ready().await;
        assert_eq!(status2, EndpointStatus::Degraded);
        assert_eq!(ready.expect("ready body").status, "not_ready");

        // Request 3: 500 HTTP Error
        let (status3, _, _) = client.fetch_vlm().await;
        assert_eq!(status3, EndpointStatus::HttpError(500));

        // Request 4: 200 Decode Error
        let (status4, _, _) = client.fetch_vikingdb().await;
        assert_eq!(status4, EndpointStatus::DecodeError);

        // Request 5: Unreachable port (bind and drop to guarantee nothing is listening)
        let dead_port = {
            let dead_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind dead port");
            dead_listener.local_addr().expect("dead addr").port()
        };
        let dead_client = TelemetryClient::new(&format!("http://127.0.0.1:{}", dead_port));
        let (status5, _, _) = dead_client.fetch_health().await;
        assert!(matches!(
            status5,
            EndpointStatus::Unreachable | EndpointStatus::Timeout
        ));
    }
}
