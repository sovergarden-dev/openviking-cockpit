//! Asynchronous telemetry client and contract-aligned models for OpenViking and local Ollama.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, RwLock};
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
pub struct QueueResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<QueueResult>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueResult {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub is_healthy: Option<bool>,
    #[serde(default)]
    pub has_errors: Option<bool>,
    #[serde(default)]
    pub status: Option<QueueStatus>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QueueStatus {
    #[serde(default)]
    pub queues: Vec<QueueItem>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueItem {
    #[serde(default)]
    pub queue: String,
    #[serde(default)]
    pub pending: usize,
    #[serde(default)]
    pub in_progress: usize,
    #[serde(default)]
    pub processed: usize,
    #[serde(default)]
    pub requeued: usize,
    #[serde(default)]
    pub errors: usize,
    #[serde(default)]
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalObserverResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<RetrievalObserverResult>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalObserverResult {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub is_healthy: Option<bool>,
    #[serde(default)]
    pub has_errors: Option<bool>,
    #[serde(default)]
    pub status: Option<RetrievalObserverStatus>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RetrievalObserverStatus {
    #[serde(default)]
    pub total_queries: usize,
    #[serde(default)]
    pub total_results: usize,
    #[serde(default)]
    pub zero_result_queries: usize,
    #[serde(default)]
    pub zero_result_rate: f64,
    #[serde(default)]
    pub avg_results_per_query: f64,
    #[serde(default)]
    pub avg_score: f64,
    #[serde(default)]
    pub max_score: f64,
    #[serde(default)]
    pub min_score: f64,
    #[serde(default)]
    pub avg_latency_ms: f64,
    #[serde(default)]
    pub max_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFindRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_type: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchFindResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<SearchFindResult>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SearchFindResult {
    #[serde(default)]
    pub memories: Vec<SearchFindHit>,
    #[serde(default)]
    pub resources: Vec<SearchFindHit>,
    #[serde(default)]
    pub skills: Vec<SearchFindHit>,
    #[serde(default)]
    pub total: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SearchFindHit {
    #[serde(default)]
    pub context_type: String,
    #[serde(default)]
    pub uri: String,
    #[serde(default)]
    pub level: Option<i32>,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default, rename = "abstract")]
    pub abstract_text: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentReadResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VikingDirEntry {
    pub name: String,
    pub uri: String,
    pub is_dir: bool,
}

fn validate_viking_uri(uri: &str) -> Result<&str, String> {
    let clean = uri.trim();
    if !clean.starts_with("viking://") || clean.contains("..") {
        return Err("URI must start with 'viking://' and contain no '..' segments".to_string());
    }
    Ok(clean)
}

/// RFC 3986 unreserved byte percent-encoder for query parameters (`uri=viking://...`).
pub fn percent_encode_query_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for &b in input.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleSummary {
    pub total_starts: usize,
    pub total_crashes: usize,
    #[serde(default)]
    pub total_hang_kills: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_exit_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_uptime_s: Option<f64>,
}

/// Reads the trailing 256 KiB of `logs/lifecycle.jsonl` (`ov_lifecycle.py`) to summarize starts and non-zero crashes.
pub fn read_lifecycle_summary(path: &Path) -> Option<LifecycleSummary> {
    let mut file = fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let max_tail: u64 = 262_144;
    if len > max_tail {
        let _ = file.seek(SeekFrom::Start(len - max_tail));
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    if len > max_tail {
        let _ = lines.next();
    }

    let mut total_starts = 0usize;
    let mut total_crashes = 0usize;
    let mut total_hang_kills = 0usize;
    let mut last_exit_hex = None;
    let mut last_uptime_s = None;
    let mut parsed_any = false;

    for ln in lines {
        let trimmed = ln.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let Some(ev) = val.get("event").and_then(|v| v.as_str()) else {
            continue;
        };
        parsed_any = true;
        match ev {
            "start" => total_starts += 1,
            "hang-killed" => total_hang_kills += 1,
            "exit" => {
                let code = val.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0);
                if code != 0 {
                    total_crashes += 1;
                }
                last_exit_hex = val
                    .get("exit_code_hex")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                last_uptime_s = val.get("uptime_s").and_then(|v| v.as_f64());
            }
            "spawn-failed" | "resolve-failed" => {
                total_crashes += 1;
            }
            _ => {}
        }
    }

    if !parsed_any {
        return None;
    }
    Some(LifecycleSummary {
        total_starts,
        total_crashes,
        total_hang_kills,
        last_exit_hex,
        last_uptime_s,
    })
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

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<QueueResponse>,
    #[serde(default = "default_ollama_status")]
    pub queue_status: EndpointStatus,
    #[serde(default)]
    pub queue_latency_ms: u64,

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleSummary>,
}

fn default_ollama_status() -> EndpointStatus {
    EndpointStatus::Unreachable
}

impl TelemetrySnapshot {
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
pub struct SlowTelemetryCache {
    pub vikingdb: (EndpointStatus, Option<VikingDbResponse>, u64),
    pub memories: (EndpointStatus, Option<MemoriesStatsResponse>, u64),
    pub queue: (EndpointStatus, Option<QueueResponse>, u64),
}

impl SlowTelemetryCache {
    pub fn all_ok(&self) -> bool {
        self.vikingdb.0 == EndpointStatus::Ok
            && self.memories.0 == EndpointStatus::Ok
            && self.queue.0 == EndpointStatus::Ok
    }
}

#[derive(Debug, Clone)]
pub struct TelemetryClient {
    base_url: String,
    ollama_base_url: String,
    api_key: Arc<RwLock<Option<RedactedApiKey>>>,
    http: reqwest::Client,
    slow_http: reqwest::Client,
    search_http: reqwest::Client,
}

impl Default for TelemetryClient {
    fn default() -> Self {
        Self::new("http://127.0.0.1:19330")
    }
}

impl TelemetryClient {
    pub fn try_new(base_url: &str) -> Result<Self, TelemetryError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(1500))
            .connect_timeout(Duration::from_millis(400))
            .no_proxy()
            .build()?;
        let slow_http = reqwest::Client::builder()
            .timeout(Duration::from_millis(4000))
            .connect_timeout(Duration::from_millis(500))
            .no_proxy()
            .build()?;
        let search_http = reqwest::Client::builder()
            .timeout(Duration::from_secs(12))
            .connect_timeout(Duration::from_millis(500))
            .no_proxy()
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            ollama_base_url: "http://127.0.0.1:21434".to_string(),
            api_key: Arc::new(RwLock::new(None)),
            http,
            slow_http,
            search_http,
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

    pub fn set_api_key(&self, key: Option<String>) {
        let next = key
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .map(RedactedApiKey);
        if let Ok(mut guard) = self.api_key.write() {
            *guard = next;
        }
    }

    pub fn with_api_key(self, key: Option<String>) -> Self {
        self.set_api_key(key);
        self
    }

    fn attach_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Ok(guard) = self.api_key.read() {
            if let Some(ref key) = *guard {
                return req.header("X-API-Key", &key.0).bearer_auth(&key.0);
            }
        }
        req
    }

    async fn probe_url_with_client<T: for<'de> Deserialize<'de>>(
        &self,
        client: &reqwest::Client,
        url: &str,
        include_auth: bool,
    ) -> (EndpointStatus, Option<T>, u64) {
        let start = Instant::now();
        let mut req = client.get(url);
        if include_auth {
            req = self.attach_auth(req);
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

    async fn probe_url<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        include_auth: bool,
    ) -> (EndpointStatus, Option<T>, u64) {
        self.probe_url_with_client(&self.http, url, include_auth)
            .await
    }

    async fn probe<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> (EndpointStatus, Option<T>, u64) {
        let url = format!("{}{}", self.base_url, path);
        self.probe_url_with_client(&self.http, &url, true).await
    }

    async fn probe_slow<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> (EndpointStatus, Option<T>, u64) {
        let url = format!("{}{}", self.base_url, path);
        self.probe_url_with_client(&self.slow_http, &url, true)
            .await
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
        let req = self.attach_auth(
            self.http
                .post(&url)
                .json(&serde_json::json!({ "index": slot_index })),
        );
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
        self.probe_slow("/api/v1/observer/vikingdb?format=json")
            .await
    }

    pub async fn fetch_memories(&self) -> (EndpointStatus, Option<MemoriesStatsResponse>, u64) {
        self.probe_slow("/api/v1/stats/memories").await
    }

    pub async fn fetch_queue(&self) -> (EndpointStatus, Option<QueueResponse>, u64) {
        self.probe_slow("/api/v1/observer/queue?format=json").await
    }

    pub async fn fetch_retrieval_observer(
        &self,
    ) -> (EndpointStatus, Option<RetrievalObserverResponse>, u64) {
        self.probe_slow("/api/v1/observer/retrieval?format=json")
            .await
    }

    /// Read-only semantic search via `POST /api/v1/search/find` (uses local embedding model only, zero VLM calls).
    pub async fn search_find(
        &self,
        body: &SearchFindRequest,
    ) -> Result<(SearchFindResult, u64), String> {
        if body.query.trim().is_empty() {
            return Err("Query must not be empty".to_string());
        }
        if let Some(ref target) = body.target_uri {
            if !target.trim().is_empty() && !target.starts_with("viking://") {
                return Err("Target URI must start with 'viking://'".to_string());
            }
        }
        let start = Instant::now();
        let url = format!("{}/api/v1/search/find", self.base_url);
        let req = self.attach_auth(self.search_http.post(&url).json(body));
        let resp = req.send().await.map_err(|e| {
            if e.is_timeout() {
                "Semantic search timed out (check OpenViking & Ollama)".to_string()
            } else {
                "OpenViking semantic search endpoint unreachable".to_string()
            }
        })?;
        let latency_ms = start.elapsed().as_millis() as u64;
        let code = resp.status();
        if !code.is_success() {
            return Err(format!(
                "Semantic search failed with HTTP {}",
                code.as_u16()
            ));
        }
        let parsed = resp
            .json::<SearchFindResponse>()
            .await
            .map_err(|_| "Failed to decode /api/v1/search/find response".to_string())?;
        Ok((parsed.result.unwrap_or_default(), latency_ms))
    }

    /// Read-only content fetch for a validated `viking://` URI via `GET /api/v1/content/read`.
    pub async fn read_content(&self, uri: &str, max_chars: usize) -> Result<String, String> {
        let clean = validate_viking_uri(uri)?;
        let capped_limit = max_chars.clamp(256, 32_768);
        let encoded_uri = percent_encode_query_component(clean);
        let url = format!(
            "{}/api/v1/content/read?uri={}&limit={}",
            self.base_url, encoded_uri, capped_limit
        );
        let req = self.attach_auth(self.search_http.get(&url));
        let resp = req.send().await.map_err(|e| {
            if e.is_timeout() {
                "Content read timed out".to_string()
            } else {
                "OpenViking content endpoint unreachable".to_string()
            }
        })?;
        let code = resp.status();
        if !code.is_success() {
            return Err(format!("Content read failed with HTTP {}", code.as_u16()));
        }
        let parsed = resp
            .json::<ContentReadResponse>()
            .await
            .map_err(|_| "Failed to decode /api/v1/content/read response".to_string())?;
        Ok(parsed.result.unwrap_or_default())
    }

    /// Read-only directory listing for a validated `viking://` URI via `GET /api/v1/fs/ls`.
    pub async fn list_dir(&self, uri: &str, limit: usize) -> Result<Vec<VikingDirEntry>, String> {
        let clean = validate_viking_uri(uri)?;
        let capped_limit = limit.clamp(1, 200);
        let encoded_uri = percent_encode_query_component(clean);
        let url = format!(
            "{}/api/v1/fs/ls?uri={}&limit={}",
            self.base_url, encoded_uri, capped_limit
        );
        let req = self.attach_auth(self.search_http.get(&url));
        let resp = req.send().await.map_err(|e| {
            if e.is_timeout() {
                "Directory listing timed out".to_string()
            } else {
                "OpenViking filesystem endpoint unreachable".to_string()
            }
        })?;
        let code = resp.status();
        if !code.is_success() {
            return Err(format!(
                "Directory listing failed with HTTP {}",
                code.as_u16()
            ));
        }
        let parsed: Value = resp
            .json()
            .await
            .map_err(|_| "Failed to decode /api/v1/fs/ls response".to_string())?;
        let raw_result = parsed.get("result");
        let items: &[Value] = match raw_result {
            Some(Value::Array(arr)) => arr.as_slice(),
            Some(Value::Object(obj)) => obj
                .get("entries")
                .or_else(|| obj.get("items"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[]),
            _ => &[],
        };

        let base_trimmed = clean.trim_end_matches('/');
        let mut entries = Vec::new();
        for item in items.iter().take(capped_limit) {
            if let Some(s) = item.as_str() {
                let is_dir = s.ends_with('/');
                let name = s.trim_matches('/').to_string();
                if name.is_empty() {
                    continue;
                }
                entries.push(VikingDirEntry {
                    uri: format!("{}/{}", base_trimmed, name),
                    name,
                    is_dir,
                });
            } else if let Some(obj) = item.as_object() {
                let raw_name = obj
                    .get("name")
                    .or_else(|| obj.get("path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let is_dir = obj
                    .get("isDir")
                    .or_else(|| obj.get("is_dir"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or_else(|| raw_name.ends_with('/'));
                let explicit_uri = obj
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|u| u.starts_with("viking://"));
                let mut name = raw_name.trim_matches('/').to_string();
                if name.is_empty() {
                    if let Some(u) = explicit_uri {
                        name = u
                            .strip_prefix("viking://")
                            .unwrap_or(u)
                            .trim_end_matches('/')
                            .rsplit('/')
                            .next()
                            .unwrap_or("")
                            .to_string();
                    }
                }
                if name.is_empty() {
                    continue;
                }
                let entry_uri = explicit_uri
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| format!("{}/{}", base_trimmed, name));
                entries.push(VikingDirEntry {
                    name,
                    uri: entry_uri,
                    is_dir,
                });
            }
        }
        entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
        Ok(entries)
    }

    pub async fn fetch_ollama_tags(&self) -> (EndpointStatus, Vec<String>, u64) {
        let url = format!("{}/api/tags", self.ollama_base_url);
        let (status, parsed, latency) = self.probe_url::<OllamaTagsResponse>(&url, false).await;
        let models = parsed
            .map(|p| p.models.into_iter().map(|m| m.name).collect())
            .unwrap_or_default();
        (status, models, latency)
    }

    pub async fn fetch_snapshot_tiered(
        &self,
        expected_embedding_model: Option<&str>,
        cached_slow: Option<&SlowTelemetryCache>,
    ) -> (TelemetrySnapshot, SlowTelemetryCache) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (h, r, v, ol) = tokio::join!(
            self.fetch_health(),
            self.fetch_ready(),
            self.fetch_vlm(),
            self.fetch_ollama_tags(),
        );

        let server_up = h.0 == EndpointStatus::Ok && h.1.as_ref().is_some_and(|body| body.healthy);
        let (db, m, q) = if h.0 != EndpointStatus::Ok {
            (
                (h.0.clone(), None, 0),
                (h.0.clone(), None, 0),
                (h.0.clone(), None, 0),
            )
        } else if let (Some(cache), true) = (cached_slow, server_up) {
            (
                cache.vikingdb.clone(),
                cache.memories.clone(),
                cache.queue.clone(),
            )
        } else {
            tokio::join!(
                self.fetch_vikingdb(),
                self.fetch_memories(),
                self.fetch_queue()
            )
        };

        let slow_cache = SlowTelemetryCache {
            vikingdb: db.clone(),
            memories: m.clone(),
            queue: q.clone(),
        };

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

            queue: q.1,
            queue_status: q.0,
            queue_latency_ms: q.2,

            ollama_status: ol.0,
            ollama_models: ol.1,
            ollama_latency_ms: ol.2,
            expected_embedding_model: expected.clone(),
            embedding_model_ready: None,
            lifecycle: None,
        };

        if let Some(ref model_name) = expected {
            let ready =
                snap.ollama_status == EndpointStatus::Ok && snap.has_ollama_model(model_name);
            snap.embedding_model_ready = Some(ready);
        }

        (snap, slow_cache)
    }
}

pub const COLD_BOOT_GRACE_SECS: u64 = 75;

/// Stateful per-incident tracker preventing repeat tray notification storms during sustained outages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncidentTracker {
    pub server_down_notified: bool,
    pub embedding_missing_notified: bool,
    pub failover_slot_notified: Option<usize>,
    pub boot_ready_seen: bool,
}

/// Uptime-aware incident evaluator that suppresses cold-boot warnings for the first `75s`
/// until the server reaches `/ready` once after launch.
pub fn evaluate_telemetry_incidents_with_uptime(
    tracker: &mut IncidentTracker,
    snapshot: &TelemetrySnapshot,
    notify_on_down: bool,
    notify_on_failover: bool,
    uptime_secs: u64,
) -> Vec<(String, String)> {
    let mut alerts = Vec::new();

    let server_healthy = snapshot.health_status == EndpointStatus::Ok
        && snapshot.health.as_ref().is_some_and(|h| h.healthy)
        && snapshot.ready_status == EndpointStatus::Ok
        && snapshot.ready.as_ref().is_some_and(|r| r.status == "ready");

    if server_healthy {
        tracker.boot_ready_seen = true;
    }
    let in_cold_boot_grace = !tracker.boot_ready_seen && uptime_secs < COLD_BOOT_GRACE_SECS;

    if !server_healthy {
        if notify_on_down && !in_cold_boot_grace && !tracker.server_down_notified {
            tracker.server_down_notified = true;
            alerts.push((
                "CẢNH BÁO: OpenViking ngắt kết nối".to_string(),
                "Dịch vụ trên cổng 19330 không phản hồi hoặc chưa sẵn sàng.".to_string(),
            ));
        }
    } else {
        tracker.server_down_notified = false;
    }

    match snapshot.embedding_model_ready {
        Some(false) => {
            if notify_on_down && !in_cold_boot_grace && !tracker.embedding_missing_notified {
                tracker.embedding_missing_notified = true;
                let model = snapshot
                    .expected_embedding_model
                    .as_deref()
                    .unwrap_or("qwen3-embedding:0.6b");
                alerts.push((
                    "CẢNH BÁO: Thiếu model Embedding".to_string(),
                    format!(
                        "Ollama đang thiếu model '{}'; tìm kiếm ngữ nghĩa sẽ lỗi 404.",
                        model
                    ),
                ));
            }
        }
        Some(true) => {
            tracker.embedding_missing_notified = false;
        }
        None => {}
    }

    if let Some(vlm_res) = snapshot.vlm.as_ref().and_then(|v| v.result.as_ref()) {
        let idx = vlm_res.index.unwrap_or(0);
        let manual_hold = vlm_res.manual_hold.unwrap_or(false);
        if idx > 0 && !manual_hold {
            if notify_on_failover && tracker.failover_slot_notified != Some(idx) {
                tracker.failover_slot_notified = Some(idx);
                alerts.push((
                    "ĐỊNH TUYẾN: Tự động chuyển Slot dự phòng".to_string(),
                    format!(
                        "OpenViking đã chuyển sang Slot dự phòng #{} do lỗi từ Slot chính.",
                        idx
                    ),
                ));
            }
        } else {
            tracker.failover_slot_notified = None;
        }
    }

    alerts
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
    fn test_has_ollama_model_matches_exact_and_latest_tags() {
        let snapshot = TelemetrySnapshot {
            timestamp_ms: 1000,
            health: None,
            health_status: EndpointStatus::Ok,
            health_latency_ms: 5,
            ready: None,
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
            queue: None,
            queue_status: EndpointStatus::Ok,
            queue_latency_ms: 4,
            ollama_status: EndpointStatus::Ok,
            ollama_models: vec![
                "qwen3-embedding:0.6b".to_string(),
                "nomic-embed-text:latest".to_string(),
            ],
            ollama_latency_ms: 3,
            expected_embedding_model: Some("qwen3-embedding:0.6b".to_string()),
            embedding_model_ready: Some(true),
            lifecycle: None,
        };

        assert!(snapshot.has_ollama_model("qwen3-embedding:0.6b"));
        assert!(snapshot.has_ollama_model("QWEN3-EMBEDDING:0.6B"));
        assert!(snapshot.has_ollama_model("nomic-embed-text"));
        assert!(!snapshot.has_ollama_model("bge-m3"));
        assert!(!snapshot.has_ollama_model("   "));
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

    #[test]
    fn test_incident_tracker_debounces_and_distinguishes_manual_hold() {
        let mut tracker = IncidentTracker::default();
        let mut snap = TelemetrySnapshot {
            timestamp_ms: 1,
            health: Some(HealthResponse {
                status: "ok".to_string(),
                healthy: true,
                version: Some("0.5.5".to_string()),
                auth_mode: None,
            }),
            health_status: EndpointStatus::Ok,
            health_latency_ms: 2,
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
            ready_latency_ms: 2,
            vlm: Some(VlmActiveResponse {
                status: "ok".to_string(),
                result: Some(VlmActiveResult {
                    kind: Some("MultiCredentialVLM".to_string()),
                    index: Some(0),
                    n: Some(4),
                    manual_hold: Some(false),
                    credential_ids: None,
                }),
                error: None,
                telemetry: None,
                profile: None,
            }),
            vlm_status: EndpointStatus::Ok,
            vlm_latency_ms: 2,
            vikingdb: None,
            vikingdb_status: EndpointStatus::Ok,
            vikingdb_latency_ms: 2,
            memories: None,
            memories_status: EndpointStatus::Ok,
            memories_latency_ms: 2,
            queue: None,
            queue_status: EndpointStatus::Ok,
            queue_latency_ms: 2,
            ollama_status: EndpointStatus::Ok,
            ollama_models: vec!["qwen3-embedding:0.6b".to_string()],
            ollama_latency_ms: 2,
            expected_embedding_model: Some("qwen3-embedding:0.6b".to_string()),
            embedding_model_ready: Some(false),
            lifecycle: None,
        };

        // 1. Missing embedding fires once, then suppresses duplicates until restored
        let a1 = evaluate_telemetry_incidents_with_uptime(
            &mut tracker,
            &snap,
            true,
            true,
            COLD_BOOT_GRACE_SECS,
        );
        assert_eq!(a1.len(), 1);
        assert!(a1[0].1.contains("qwen3-embedding:0.6b"));
        assert!(evaluate_telemetry_incidents_with_uptime(
            &mut tracker,
            &snap,
            true,
            true,
            COLD_BOOT_GRACE_SECS,
        )
        .is_empty());

        // Restore embedding -> resets latch
        snap.embedding_model_ready = Some(true);
        assert!(evaluate_telemetry_incidents_with_uptime(
            &mut tracker,
            &snap,
            true,
            true,
            COLD_BOOT_GRACE_SECS,
        )
        .is_empty());
        assert!(!tracker.embedding_missing_notified);

        // 2. Manual switch (manual_hold=true) must NOT trigger failover alarm
        snap.vlm.as_mut().unwrap().result.as_mut().unwrap().index = Some(1);
        snap.vlm
            .as_mut()
            .unwrap()
            .result
            .as_mut()
            .unwrap()
            .manual_hold = Some(true);
        assert!(evaluate_telemetry_incidents_with_uptime(
            &mut tracker,
            &snap,
            true,
            true,
            COLD_BOOT_GRACE_SECS,
        )
        .is_empty());

        // 3. Automatic failover (index=1, manual_hold=false) fires once
        snap.vlm
            .as_mut()
            .unwrap()
            .result
            .as_mut()
            .unwrap()
            .manual_hold = Some(false);
        let f1 = evaluate_telemetry_incidents_with_uptime(
            &mut tracker,
            &snap,
            true,
            true,
            COLD_BOOT_GRACE_SECS,
        );
        assert_eq!(f1.len(), 1);
        assert!(evaluate_telemetry_incidents_with_uptime(
            &mut tracker,
            &snap,
            true,
            true,
            COLD_BOOT_GRACE_SECS,
        )
        .is_empty());
    }

    #[test]
    fn test_cold_boot_grace_window_suppresses_early_alerts_until_75s_or_ready() {
        let mut down_snap = TelemetrySnapshot {
            timestamp_ms: 1,
            health: None,
            health_status: EndpointStatus::Unreachable,
            health_latency_ms: 0,
            ready: None,
            ready_status: EndpointStatus::Unreachable,
            ready_latency_ms: 0,
            vlm: None,
            vlm_status: EndpointStatus::Unreachable,
            vlm_latency_ms: 0,
            vikingdb: None,
            vikingdb_status: EndpointStatus::Unreachable,
            vikingdb_latency_ms: 0,
            memories: None,
            memories_status: EndpointStatus::Unreachable,
            memories_latency_ms: 0,
            queue: None,
            queue_status: EndpointStatus::Unreachable,
            queue_latency_ms: 0,
            ollama_status: EndpointStatus::Unreachable,
            ollama_models: Vec::new(),
            ollama_latency_ms: 0,
            expected_embedding_model: None,
            embedding_model_ready: None,
            lifecycle: None,
        };

        let mut tracker = IncidentTracker::default();
        assert!(
            evaluate_telemetry_incidents_with_uptime(&mut tracker, &down_snap, true, true, 10)
                .is_empty()
        );
        assert!(!tracker.server_down_notified);

        let after_grace =
            evaluate_telemetry_incidents_with_uptime(&mut tracker, &down_snap, true, true, 75);
        assert_eq!(after_grace.len(), 1);
        assert!(tracker.server_down_notified);

        // If server comes up early (t=20s) and drops later (t=25s), alert fires immediately without waiting 75s
        let mut boot_tracker = IncidentTracker::default();
        down_snap.health = Some(HealthResponse {
            status: "ok".to_string(),
            healthy: true,
            version: Some("0.5.5".to_string()),
            auth_mode: None,
        });
        down_snap.health_status = EndpointStatus::Ok;
        down_snap.ready = Some(ReadyResponse {
            status: "ready".to_string(),
            checks: ReadyChecks {
                agfs: None,
                vectordb: None,
                api_key_manager: None,
                embedding: None,
                ollama: None,
            },
        });
        down_snap.ready_status = EndpointStatus::Ok;
        assert!(evaluate_telemetry_incidents_with_uptime(
            &mut boot_tracker,
            &down_snap,
            true,
            true,
            20
        )
        .is_empty());
        assert!(boot_tracker.boot_ready_seen);

        down_snap.health_status = EndpointStatus::Unreachable;
        let dropped =
            evaluate_telemetry_incidents_with_uptime(&mut boot_tracker, &down_snap, true, true, 25);
        assert_eq!(dropped.len(), 1);
    }

    #[test]
    fn test_read_lifecycle_summary_counts_starts_and_crashes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("lifecycle.jsonl");
        let lines = concat!(
            r#"{"event":"start","run_id":"r1","child_pid":100}"#,
            "\n",
            r#"{"event":"hang-killed","run_id":"r1","child_pid":100,"consecutive_failures":3,"uptime_s":12.0}"#,
            "\n",
            r#"{"event":"exit","run_id":"r1","exit_code":3,"exit_code_hex":"0x00000003","uptime_s":12.5}"#,
            "\n",
            r#"{"event":"start","run_id":"r2","child_pid":101}"#,
            "\n"
        );
        std::fs::write(&log_path, lines).expect("write lifecycle.jsonl");

        let sum = read_lifecycle_summary(&log_path).expect("parse lifecycle summary");
        assert_eq!(sum.total_starts, 2);
        assert_eq!(sum.total_crashes, 1);
        assert_eq!(sum.total_hang_kills, 1);
        assert_eq!(sum.last_exit_hex.as_deref(), Some("0x00000003"));
        assert_eq!(sum.last_uptime_s, Some(12.5));
    }

    #[tokio::test]
    async fn test_fetch_snapshot_tiered_reuses_slow_cache_without_rehitting_memories() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);
        let memories_hits = Arc::new(AtomicUsize::new(0));
        let memories_hits_srv = Arc::clone(&memories_hits);

        tokio::spawn(async move {
            for _ in 0..11 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");
                    let body = if first_line.starts_with("GET /health ") {
                        r#"{"status":"ok","healthy":true,"version":"0.5.5"}"#
                    } else if first_line.starts_with("GET /ready ") {
                        r#"{"status":"ready","checks":{"vectordb":"ok"}}"#
                    } else if first_line.starts_with("GET /api/v1/observer/vlm/active ") {
                        r#"{"status":"ok","result":{"kind":"MultiCredentialVLM","index":0,"n":1,"manual_hold":false}}"#
                    } else if first_line.starts_with("GET /api/v1/observer/vikingdb") {
                        r#"{"status":"ok","result":{"is_healthy":true,"has_errors":false,"status":{"vector_count":99,"dimension":1024}}}"#
                    } else if first_line.starts_with("GET /api/v1/stats/memories ") {
                        memories_hits_srv.fetch_add(1, Ordering::SeqCst);
                        r#"{"status":"ok","result":{"total_memories":55}}"#
                    } else if first_line.starts_with("GET /api/v1/observer/queue") {
                        r#"{"status":"ok","result":{"name":"queue","is_healthy":true,"has_errors":false,"status":{"queues":[]}}}"#
                    } else {
                        r#"{"models":[]}"#
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
            }
        });

        let client = TelemetryClient::new(&base_url).with_ollama_base_url(&base_url);
        let (snap1, cache1) = client.fetch_snapshot_tiered(None, None).await;
        assert!(cache1.all_ok());
        assert_eq!(memories_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            snap1
                .memories
                .as_ref()
                .and_then(|m| m.result.as_ref())
                .and_then(|r| r.total_memories),
            Some(55)
        );

        let (snap2, _cache2) = client.fetch_snapshot_tiered(None, Some(&cache1)).await;
        assert_eq!(memories_hits.load(Ordering::SeqCst), 1);
        assert_eq!(snap2.health_status, EndpointStatus::Ok);
        assert_eq!(
            snap2
                .memories
                .as_ref()
                .and_then(|m| m.result.as_ref())
                .and_then(|r| r.total_memories),
            Some(55)
        );
    }

    #[tokio::test]
    async fn test_fetch_snapshot_tiered_short_circuits_on_health_failure_and_all_ok_rejects_errors()
    {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);
        let memories_hits = Arc::new(AtomicUsize::new(0));
        let memories_hits_srv = Arc::clone(&memories_hits);

        tokio::spawn(async move {
            for _ in 0..8 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");
                    let (status_line, body) = if first_line.starts_with("GET /health ") {
                        ("HTTP/1.1 503 Service Unavailable", r#"{"healthy":false}"#)
                    } else if first_line.starts_with("GET /api/v1/stats/memories ") {
                        memories_hits_srv.fetch_add(1, Ordering::SeqCst);
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"status":"ok","result":{"total_memories":1}}"#,
                        )
                    } else if first_line.starts_with("GET /api/tags ") {
                        ("HTTP/1.1 200 OK", r#"{"models":[]}"#)
                    } else {
                        ("HTTP/1.1 503 Service Unavailable", r#"{"status":"down"}"#)
                    };
                    let resp = format!(
                        "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status_line,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
            }
        });

        let client = TelemetryClient::new(&base_url).with_ollama_base_url(&base_url);
        let (snap, cache) = client.fetch_snapshot_tiered(None, None).await;
        assert_eq!(snap.health_status, EndpointStatus::HttpError(503));
        assert_eq!(snap.vikingdb_status, EndpointStatus::HttpError(503));
        assert_eq!(snap.memories_status, EndpointStatus::HttpError(503));
        assert_eq!(snap.queue_status, EndpointStatus::HttpError(503));
        assert_eq!(memories_hits.load(Ordering::SeqCst), 0);
        assert!(!cache.all_ok());
    }

    #[tokio::test]
    async fn test_queue_search_and_content_read_contracts_and_uri_guards() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let q_json = r#"{"status":"ok","result":{"name":"queue","is_healthy":true,"has_errors":false,"status":{"queues":[{"queue":"Embedding","pending":2,"in_progress":1,"processed":8,"requeued":0,"errors":1,"total":11},{"queue":"Semantic","pending":0,"in_progress":0,"processed":5,"requeued":1,"errors":0,"total":5}]}}}"#;
        let q_parsed: QueueResponse = serde_json::from_str(q_json).expect("parse queue json");
        let q_status = q_parsed.result.unwrap().status.unwrap();
        assert_eq!(q_status.queues.len(), 2);
        assert_eq!(q_status.queues[0].pending, 2);
        assert_eq!(q_status.queues[0].in_progress, 1);
        assert_eq!(q_status.queues[0].processed, 8);
        assert_eq!(q_status.queues[0].errors, 1);
        assert_eq!(q_status.queues[1].processed, 5);
        assert_eq!(q_status.queues[1].requeued, 1);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}", port);

        tokio::spawn(async move {
            for _ in 0..3 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                    let req_lower = req_str.to_ascii_lowercase();
                    let authed = req_lower.contains("x-api-key: synthetic_root_key_777\r\n")
                        && req_lower.contains("authorization: bearer synthetic_root_key_777\r\n");
                    let first_line = req_str.lines().next().unwrap_or("");
                    let (status_line, body) = if !authed {
                        ("HTTP/1.1 401 Unauthorized", r#"{"status":"unauthorized"}"#)
                    } else if first_line.starts_with("POST /api/v1/search/find ") {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"status":"ok","result":{"memories":[{"context_type":"memory","uri":"viking://user/default/memories/preferences/pref_1.md","level":2,"score":0.891,"abstract":"DPAPI key policy"}],"resources":[],"skills":[],"total":1}}"#,
                        )
                    } else if first_line.starts_with(
                        "GET /api/v1/content/read?uri=viking%3A%2F%2Fuser%2Fdefault%2Fmemories%2Fpref_1.md&limit=512 ",
                    ) {
                        (
                            "HTTP/1.1 200 OK",
                            r##"{"status":"ok","result":"# DPAPI Policy\nNever write plaintext keys."}"##,
                        )
                    } else if first_line.starts_with(
                        "GET /api/v1/fs/ls?uri=viking%3A%2F%2Fuser%2Fdefault%2Fmemories&limit=20 ",
                    ) {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"status":"ok","result":[{"uri":"viking://","size":0,"isDir":true},{"uri":"viking://user/default/memories/profile.md","size":128,"isDir":false},{"uri":"viking://user/default/memories/cases","size":0,"isDir":true}]}"#,
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
            }
        });

        let client = TelemetryClient::new(&base_url);
        client.set_api_key(Some("SYNTHETIC_ROOT_KEY_777".to_string()));

        assert!(client
            .search_find(&SearchFindRequest {
                query: "   ".to_string(),
                target_uri: None,
                context_type: None,
                limit: 5,
            })
            .await
            .is_err());

        assert!(client
            .search_find(&SearchFindRequest {
                query: "dpapi".to_string(),
                target_uri: Some("http://evil.example".to_string()),
                context_type: None,
                limit: 5,
            })
            .await
            .is_err());

        let (found, _) = client
            .search_find(&SearchFindRequest {
                query: "dpapi".to_string(),
                target_uri: Some("viking://user/default/memories".to_string()),
                context_type: Some("memory".to_string()),
                limit: 5,
            })
            .await
            .expect("search_find ok");
        assert_eq!(found.memories.len(), 1);
        assert_eq!(found.memories[0].level, Some(2));

        assert!(client
            .read_content("file:///C:/Windows/win.ini", 512)
            .await
            .is_err());
        assert!(client
            .read_content("viking://user/default/../secrets", 512)
            .await
            .is_err());

        let content = client
            .read_content("viking://user/default/memories/pref_1.md", 512)
            .await
            .expect("read_content ok");
        assert!(content.contains("Never write plaintext keys."));

        assert!(client.list_dir("http://bad/uri", 20).await.is_err());
        let listed = client
            .list_dir("viking://user/default/memories", 20)
            .await
            .expect("list_dir ok");
        assert_eq!(listed.len(), 2);
        assert!(listed[0].is_dir);
        assert_eq!(listed[0].name, "cases");
        assert_eq!(listed[0].uri, "viking://user/default/memories/cases");
        assert!(!listed[1].is_dir);
        assert_eq!(listed[1].name, "profile.md");
    }
}
