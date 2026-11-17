//! Asynchronous telemetry client and contract-aligned models for OpenViking and local Ollama.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OllamaTagsResponse {
    #[serde(default)]
    pub models: Vec<OllamaModelInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OllamaModelInfo {
    pub name: String,
    #[serde(default)]
    pub size: Option<u64>,
}

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

    #[serde(default = "default_ollama_status")]
    pub ollama_status: EndpointStatus,
    #[serde(default)]
    pub ollama_models: Vec<String>,
    #[serde(default)]
    pub ollama_latency_ms: u64,
    #[serde(default)]
    pub expected_embedding_model: Option<String>,
    #[serde(default)]
    pub embedding_model_ready: Option<bool>,
}

fn default_ollama_status() -> EndpointStatus {
    EndpointStatus::Unreachable
}

impl TelemetrySnapshot {
    pub fn is_overall_healthy(&self) -> bool {
        let health_ok = self.health_status == EndpointStatus::Ok
            && self.health.as_ref().is_some_and(|h| h.healthy);
        let ready_ok = self.ready_status == EndpointStatus::Ok
            && self.ready.as_ref().is_some_and(|r| r.status == "ready");
        let embed_ok = self.embedding_model_ready.unwrap_or(true);
        health_ok && ready_ok && embed_ok
    }

    pub fn has_ollama_model(&self, target: &str) -> bool {
        let needle = target.trim();
        if needle.is_empty() {
            return false;
        }
        let needle_with_latest = if needle.contains(':') {
            None
        } else {
            Some(format!("{}:latest", needle))
        };
        self.ollama_models.iter().any(|m| {
            m.eq_ignore_ascii_case(needle)
                || needle_with_latest
                    .as_ref()
                    .is_some_and(|n| m.eq_ignore_ascii_case(n))
        })
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
struct RedactedApiKey(String);

impl fmt::Debug for RedactedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("HTTP client build failure: {0}")]
    ClientBuild(#[from] reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct TelemetryClient {
    base_url: String,
    ollama_base_url: String,
    api_key: Option<RedactedApiKey>,
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
            ollama_base_url: "http://127.0.0.1:21434".to_string(),
            api_key: None,
            http,
        })
    }

    pub fn new(base_url: &str) -> Self {
        Self::try_new(base_url).expect("Failed to build reqwest HTTP client")
    }

    pub fn with_ollama_base_url(mut self, ollama_base_url: &str) -> Self {
        self.ollama_base_url = ollama_base_url
            .trim_end_matches('/')
            .trim_end_matches("/v1")
            .to_string();
        self
    }

    pub fn with_api_key(mut self, key: Option<String>) -> Self {
        self.api_key = key
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .map(RedactedApiKey);
        self
    }

    async fn probe_url<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        include_auth: bool,
    ) -> (EndpointStatus, Option<T>, u64) {
        let start = Instant::now();
        let mut req = self.http.get(url);
        if include_auth {
            if let Some(ref key) = self.api_key {
                req = req.header("X-API-Key", &key.0).bearer_auth(&key.0);
            }
        }

        let resp = match req.send().await {
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
            // Only 503 with a parseable structured body counts as Degraded rather than hard HttpError.
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

    async fn probe<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> (EndpointStatus, Option<T>, u64) {
        let url = format!("{}{}", self.base_url, path);
        self.probe_url(&url, true).await
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

    /// Runtime VLM slot hot-switch (`POST /api/v1/observer/vlm/active` with `{"index": slot_index}`).
    /// Index `> 0` engages `manual_hold`; index `0` releases `manual_hold` without touching `ov.conf`.
    pub async fn switch_active_vlm_slot(
        &self,
        slot_index: usize,
    ) -> Result<VlmActiveResponse, String> {
        let url = format!("{}/api/v1/observer/vlm/active", self.base_url);
        let mut req = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "index": slot_index }));
        if let Some(ref key) = self.api_key {
            req = req.header("X-API-Key", &key.0).bearer_auth(&key.0);
        }
        let resp = req.send().await.map_err(|e| {
            if e.is_timeout() {
                "VLM hot-switch request timed out".to_string()
            } else {
                "VLM hot-switch endpoint unreachable".to_string()
            }
        })?;
        let code = resp.status();
        if !code.is_success() {
            return Err(format!(
                "VLM hot-switch rejected with HTTP {}",
                code.as_u16()
            ));
        }
        resp.json::<VlmActiveResponse>()
            .await
            .map_err(|_| "Failed to decode VLM hot-switch response".to_string())
    }

    pub async fn fetch_vikingdb(&self) -> (EndpointStatus, Option<VikingDbResponse>, u64) {
        self.probe("/api/v1/observer/vikingdb?format=json").await
    }

    pub async fn fetch_memories(&self) -> (EndpointStatus, Option<MemoriesStatsResponse>, u64) {
        self.probe("/api/v1/stats/memories").await
    }

    pub async fn fetch_ollama_tags(&self) -> (EndpointStatus, Vec<String>, u64) {
        let url = format!("{}/api/tags", self.ollama_base_url);
        let (status, parsed, latency) = self.probe_url::<OllamaTagsResponse>(&url, false).await;
        let models = parsed
            .map(|p| p.models.into_iter().map(|m| m.name).collect())
            .unwrap_or_default();
        (status, models, latency)
    }

    pub async fn fetch_snapshot(&self) -> TelemetrySnapshot {
        self.fetch_snapshot_with_embedding(None).await
    }

    pub async fn fetch_snapshot_with_embedding(
        &self,
        expected_embedding_model: Option<&str>,
    ) -> TelemetrySnapshot {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (h, r, v, db, m, ol) = tokio::join!(
            self.fetch_health(),
            self.fetch_ready(),
            self.fetch_vlm(),
            self.fetch_vikingdb(),
            self.fetch_memories(),
            self.fetch_ollama_tags(),
        );

        let expected = expected_embedding_model
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut snap = TelemetrySnapshot {
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

            ollama_status: ol.0,
            ollama_models: ol.1,
            ollama_latency_ms: ol.2,
            expected_embedding_model: expected.clone(),
            embedding_model_ready: None,
        };

        if let Some(ref model_name) = expected {
            let ready =
                snap.ollama_status == EndpointStatus::Ok && snap.has_ollama_model(model_name);
            snap.embedding_model_ready = Some(ready);
        }

        snap
    }
}

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
        let health_data = fs::read_to_string(get_fixture_path("health")).expect("read health.json");
        let health: HealthResponse = serde_json::from_str(&health_data).expect("parse health");
        assert_eq!(health.status, "ok");
        assert!(health.healthy);
        assert_eq!(health.version.as_deref(), Some("0.5.3"));

        let ready_data = fs::read_to_string(get_fixture_path("ready")).expect("read ready.json");
        let ready: ReadyResponse = serde_json::from_str(&ready_data).expect("parse ready");
        assert_eq!(ready.status, "ready");
        assert_eq!(ready.checks.vectordb.as_deref(), Some("ok"));

        let vlm_data =
            fs::read_to_string(get_fixture_path("vlm_active")).expect("read vlm_active.json");
        let vlm: VlmActiveResponse = serde_json::from_str(&vlm_data).expect("parse vlm_active");
        assert_eq!(vlm.status, "ok");
        let vlm_res = vlm.result.expect("vlm result");
        assert_eq!(vlm_res.kind.as_deref(), Some("MultiCredentialVLM"));
        assert_eq!(vlm_res.index, Some(0));
        assert_eq!(vlm_res.credential_ids.expect("cred ids").len(), 4);

        let db_data = fs::read_to_string(get_fixture_path("vikingdb")).expect("read vikingdb.json");
        let db: VikingDbResponse = serde_json::from_str(&db_data).expect("parse vikingdb");
        assert_eq!(db.status, "ok");
        let db_res = db.result.expect("db result");
        assert_eq!(db_res.status.expect("status").vector_count, Some(1000));

        let mem_data = fs::read_to_string(get_fixture_path("memories_stats"))
            .expect("read memories_stats.json");
        let mem: MemoriesStatsResponse =
            serde_json::from_str(&mem_data).expect("parse memories_stats");
        assert_eq!(mem.status, "ok");
        let mem_res = mem.result.expect("mem result");
        assert_eq!(mem_res.total_memories, Some(1000));
    }

    #[test]
    fn test_overall_healthy_predicate_and_embedding_gate() {
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
            ollama_status: EndpointStatus::Ok,
            ollama_models: vec!["qwen3-embedding:0.6b".to_string()],
            ollama_latency_ms: 3,
            expected_embedding_model: Some("qwen3-embedding:0.6b".to_string()),
            embedding_model_ready: Some(true),
        };

        assert!(snapshot.is_overall_healthy());
        assert!(snapshot.has_ollama_model("qwen3-embedding:0.6b"));
        assert!(!snapshot.has_ollama_model("bge-m3"));

        // Missing embedding model in Ollama must flip overall health to false even when /ready says "ok".
        snapshot.embedding_model_ready = Some(false);
        assert!(!snapshot.is_overall_healthy());
        snapshot.embedding_model_ready = Some(true);

        snapshot.ready_status = EndpointStatus::Degraded;
        assert!(!snapshot.is_overall_healthy());

        snapshot.ready_status = EndpointStatus::Ok;
        snapshot.ready.as_mut().unwrap().status = "not_ready".to_string();
        assert!(!snapshot.is_overall_healthy());

        snapshot.ready.as_mut().unwrap().status = "ready".to_string();
        snapshot.health.as_mut().unwrap().healthy = false;
        assert!(!snapshot.is_overall_healthy());
    }

    #[test]
    fn test_client_debug_redacts_api_key() {
        let client =
            TelemetryClient::default().with_api_key(Some("SYNTHETIC_SECRET_TOKEN_999".to_string()));
        let dbg = format!("{:?}", client);
        assert!(!dbg.contains("SYNTHETIC_SECRET_TOKEN_999"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_mock_http_probe_matrix_verifies_canonical_paths() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local test port");
        let port = listener.local_addr().expect("local addr").port();
        let base_url = format!("http://127.0.0.1:{}", port);

        tokio::spawn(async move {
            for _ in 0..6 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 2048];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req_line = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string();

                    let (status_line, content_type, body) = match req_line.as_str() {
                        "GET /health HTTP/1.1" => (
                            "HTTP/1.1 200 OK",
                            "application/json",
                            r#"{"status":"ok","healthy":true,"version":"0.5.3"}"#,
                        ),
                        "GET /ready HTTP/1.1" => (
                            "HTTP/1.1 503 Service Unavailable",
                            "application/json",
                            r#"{"status":"not_ready","checks":{}}"#,
                        ),
                        "GET /api/v1/observer/vlm/active HTTP/1.1" => (
                            "HTTP/1.1 500 Internal Server Error",
                            "text/plain",
                            "Server Error!",
                        ),
                        "GET /api/v1/observer/vikingdb?format=json HTTP/1.1" => {
                            ("HTTP/1.1 200 OK", "application/json", "{corrupted-json")
                        }
                        "GET /api/v1/stats/memories HTTP/1.1" => (
                            "HTTP/1.1 200 OK",
                            "application/json",
                            r#"{"status":"ok","result":{"total_memories":42}}"#,
                        ),
                        "GET /api/tags HTTP/1.1" => (
                            "HTTP/1.1 200 OK",
                            "application/json",
                            r#"{"models":[{"name":"qwen3-embedding:0.6b"}]}"#,
                        ),
                        _ => ("HTTP/1.1 404 Not Found", "text/plain", "wrong route"),
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

        let client = TelemetryClient::new(&base_url).with_ollama_base_url(&base_url);

        let (status1, health, _) = client.fetch_health().await;
        assert_eq!(status1, EndpointStatus::Ok);
        assert!(health.is_some_and(|h| h.healthy));

        let (status2, ready, _) = client.fetch_ready().await;
        assert_eq!(status2, EndpointStatus::Degraded);
        assert_eq!(ready.expect("ready body").status, "not_ready");

        let (status3, _, _) = client.fetch_vlm().await;
        assert_eq!(status3, EndpointStatus::HttpError(500));

        let (status4, _, _) = client.fetch_vikingdb().await;
        assert_eq!(status4, EndpointStatus::DecodeError);

        let (status5, mem, _) = client.fetch_memories().await;
        assert_eq!(status5, EndpointStatus::Ok);
        assert_eq!(
            mem.and_then(|m| m.result).and_then(|r| r.total_memories),
            Some(42)
        );

        let (status6, models, _) = client.fetch_ollama_tags().await;
        assert_eq!(status6, EndpointStatus::Ok);
        assert_eq!(models, vec!["qwen3-embedding:0.6b".to_string()]);

        let dead_port = {
            let dead_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind dead port");
            dead_listener.local_addr().expect("dead addr").port()
        };
        let dead_client = TelemetryClient::new(&format!("http://127.0.0.1:{}", dead_port));
        let (status7, _, _) = dead_client.fetch_health().await;
        assert!(matches!(
            status7,
            EndpointStatus::Unreachable | EndpointStatus::Timeout
        ));
    }

    #[tokio::test]
    async fn test_switch_active_vlm_slot_posts_index() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                let ok_post = req_str.starts_with("POST /api/v1/observer/vlm/active HTTP/1.1")
                    && req_str.contains(r#"{"index":2}"#);
                let (status_line, body) = if ok_post {
                    (
                        "HTTP/1.1 200 OK",
                        r#"{"status":"ok","result":{"kind":"MultiCredentialVLM","index":2,"n":4,"manual_hold":true}}"#,
                    )
                } else {
                    ("HTTP/1.1 400 Bad Request", r#"{"status":"error"}"#)
                };
                let resp = format!(
                    "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status_line,
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let client = TelemetryClient::new(&base_url);
        let switched = client
            .switch_active_vlm_slot(2)
            .await
            .expect("switch slot 2");
        let res = switched.result.expect("result");
        assert_eq!(res.index, Some(2));
        assert_eq!(res.manual_hold, Some(true));
    }
}
