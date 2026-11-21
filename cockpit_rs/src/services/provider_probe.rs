//! OpenAI-compatible provider model discovery (`/models`), single-shot chat liveness probes,
//! and cancellable multi-round latency benchmarks (`cockpit_rs` zero-secret backend).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

use crate::services::auditor_cache::presentation_sanitize_text;
use crate::services::watchlist::ProbeOutcome;

pub const DEFAULT_PROBE_TIMEOUT_MS: u64 = 20_000;
pub const MODELS_TIMEOUT_MS: u64 = 20_000;
pub const MODELS_RESPONSE_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const CHAT_PROBE_RESPONSE_MAX_BYTES: usize = 65_536;
pub const CHAT_PROBE_MAX_TOKENS: u32 = 64;
pub const MAX_BENCHMARK_ROUNDS: usize = 5;
pub const MAX_BENCHMARK_MODELS: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderModelsResult {
    pub ok: bool,
    pub ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    pub latency_ms: u64,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkModelSummary {
    pub model: String,
    pub runs: usize,
    pub ok_runs: usize,
    pub success_rate: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p90_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub best_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worst_ms: Option<u64>,
    pub error: String,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BenchmarkProgressEvent {
    Started {
        total_models: usize,
        rounds: usize,
    },
    ModelDone {
        completed: usize,
        total_models: usize,
        summary: BenchmarkModelSummary,
    },
    Completed {
        cancelled: bool,
        results: Vec<BenchmarkModelSummary>,
    },
    Failed {
        message: String,
    },
}

static PROBE_HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn probe_http_client() -> Option<&'static reqwest::Client> {
    if let Some(c) = PROBE_HTTP_CLIENT.get() {
        return Some(c);
    }
    let built = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent("OpenViking-Monitor/1.0")
        .build()
        .ok()?;
    let _ = PROBE_HTTP_CLIENT.set(built);
    PROBE_HTTP_CLIENT.get()
}

pub fn validate_provider_probe_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 || trimmed.chars().any(|c| c <= ' ') {
        return Err("Invalid Provider Base URL".to_string());
    }
    let parsed =
        reqwest::Url::parse(trimmed).map_err(|_| "Invalid Provider Base URL".to_string())?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("Provider Base URL must use http or https".to_string());
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("Provider Base URL must not embed credentials, query, or fragment".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "Missing hostname in Provider Base URL".to_string())?;
    let is_local = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if scheme == "http" && !is_local {
        return Err("Remote Provider endpoints must use HTTPS".to_string());
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn push_candidate_id(raw: &str, seen: &mut HashSet<String>, out: &mut Vec<String>) {
    let clean = raw.trim();
    if clean.is_empty()
        || clean.len() > 512
        || clean.chars().any(|c| (c as u32) < 32 || (c as u32) == 127)
    {
        return;
    }
    let key = clean.to_ascii_lowercase();
    if seen.insert(key) {
        out.push(clean.to_string());
    }
}

pub fn parse_model_ids_from_body(body: &Value) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    if let Some(items) = body.get("data").and_then(|v| v.as_array()) {
        for item in items {
            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                push_candidate_id(id, &mut seen, &mut out);
            } else if let Some(s) = item.as_str() {
                push_candidate_id(s, &mut seen, &mut out);
            }
        }
    }
    if out.is_empty() {
        if let Some(items) = body.get("models").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(id) = item
                    .get("id")
                    .or_else(|| item.get("name"))
                    .and_then(|v| v.as_str())
                {
                    push_candidate_id(id, &mut seen, &mut out);
                } else if let Some(s) = item.as_str() {
                    push_candidate_id(s, &mut seen, &mut out);
                }
            }
        }
    }
    out
}

async fn read_bounded_bytes(
    resp: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if resp
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        return Err("response_too_large".to_string());
    }
    let mut buf = Vec::with_capacity(1024);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| if e.is_timeout() { "timeout" } else { "network" }.to_string())?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err("response_too_large".to_string());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

async fn fetch_models_once(
    client: &reqwest::Client,
    url: &str,
    resolved_key: &str,
) -> ProviderModelsResult {
    let start = Instant::now();
    let mut req = client
        .get(url)
        .timeout(Duration::from_millis(MODELS_TIMEOUT_MS))
        .header("Accept", "application/json");
    if !resolved_key.trim().is_empty() {
        req = req.bearer_auth(resolved_key.trim());
    }

    let mut resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let raw_err = if e.is_timeout() {
                "Request timed out while listing /models".to_string()
            } else if e.is_redirect() {
                "Blocked unsafe redirect from /models".to_string()
            } else {
                format!("Network error contacting provider: {}", e)
            };
            return ProviderModelsResult {
                ok: false,
                ids: Vec::new(),
                status_code: None,
                latency_ms,
                error: presentation_sanitize_text(&raw_err, Some(resolved_key)),
            };
        }
    };

    let code = resp.status().as_u16();
    let latency_ms = start.elapsed().as_millis() as u64;
    if !resp.status().is_success() {
        let snippet = read_bounded_bytes(&mut resp, 4096)
            .await
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        let clean_snippet = presentation_sanitize_text(snippet.trim(), Some(resolved_key));
        let err_msg = if clean_snippet.is_empty() {
            format!("HTTP {}", code)
        } else {
            let truncated: String = clean_snippet.chars().take(180).collect();
            format!("HTTP {}: {}", code, truncated)
        };
        return ProviderModelsResult {
            ok: false,
            ids: Vec::new(),
            status_code: Some(code),
            latency_ms,
            error: err_msg,
        };
    }

    let bytes = match read_bounded_bytes(&mut resp, MODELS_RESPONSE_MAX_BYTES).await {
        Ok(b) => b,
        Err(err) => {
            return ProviderModelsResult {
                ok: false,
                ids: Vec::new(),
                status_code: Some(code),
                latency_ms,
                error: format!("Failed reading /models body: {}", err),
            };
        }
    };

    let parsed: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return ProviderModelsResult {
                ok: false,
                ids: Vec::new(),
                status_code: Some(code),
                latency_ms,
                error: "Provider /models returned invalid JSON".to_string(),
            };
        }
    };

    let ids = parse_model_ids_from_body(&parsed);
    if ids.is_empty() {
        return ProviderModelsResult {
            ok: false,
            ids: Vec::new(),
            status_code: Some(code),
            latency_ms,
            error: "No models returned by provider /models".to_string(),
        };
    }

    ProviderModelsResult {
        ok: true,
        ids,
        status_code: Some(code),
        latency_ms,
        error: String::new(),
    }
}

pub async fn list_provider_models(api_base: &str, resolved_key: &str) -> ProviderModelsResult {
    let clean_base = match validate_provider_probe_url(api_base) {
        Ok(b) => b,
        Err(err) => {
            return ProviderModelsResult {
                ok: false,
                ids: Vec::new(),
                status_code: None,
                latency_ms: 0,
                error: presentation_sanitize_text(&err, Some(resolved_key)),
            };
        }
    };

    let Some(client) = probe_http_client() else {
        return ProviderModelsResult {
            ok: false,
            ids: Vec::new(),
            status_code: None,
            latency_ms: 0,
            error: "Failed to initialize HTTP client".to_string(),
        };
    };

    let url = format!("{}/models", clean_base);
    let first = fetch_models_once(client, &url, resolved_key).await;
    if first.ok || first.status_code.is_some() {
        return first;
    }
    fetch_models_once(client, &url, resolved_key).await
}

fn is_chat_response_alive(body: &Value) -> bool {
    if body.get("error").is_some_and(|e| !e.is_null()) {
        return false;
    }
    let Some(choice) = body
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
    else {
        return false;
    };
    let finish = choice.get("finish_reason").and_then(|v| v.as_str());
    if matches!(finish, Some("stop" | "length")) {
        return true;
    }
    let Some(msg) = choice.get("message") else {
        return false;
    };
    let has_content = msg
        .get("content")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty());
    let has_tools = msg
        .get("tool_calls")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    let has_reasoning = ["reasoning", "reasoning_content"].iter().any(|k| {
        msg.get(*k)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty())
    });
    has_content || has_tools || has_reasoning
}

pub async fn probe_chat_model(
    model: &str,
    api_base: &str,
    resolved_key: &str,
    timeout_ms: u64,
) -> ProbeOutcome {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let clean_model = model.trim();
    if clean_model.is_empty() {
        return ProbeOutcome {
            ok: false,
            category: "request".to_string(),
            status_code: None,
            ms: None,
            at: now,
            text: Some("Missing model".to_string()),
        };
    }

    let clean_base = match validate_provider_probe_url(api_base) {
        Ok(b) => b,
        Err(_) => {
            return ProbeOutcome {
                ok: false,
                category: "invalid_url".to_string(),
                status_code: None,
                ms: None,
                at: now,
                text: Some("Invalid URL".to_string()),
            };
        }
    };

    let Some(client) = probe_http_client() else {
        return ProbeOutcome {
            ok: false,
            category: "client_error".to_string(),
            status_code: None,
            ms: None,
            at: now,
            text: Some("Client error".to_string()),
        };
    };

    let url = format!("{}/chat/completions", clean_base);
    let body = json!({
        "model": clean_model,
        "messages": [{"role": "user", "content": "Reply exactly: OK"}],
        "max_tokens": CHAT_PROBE_MAX_TOKENS,
        "temperature": 0
    });

    let effective_timeout = timeout_ms.clamp(1_000, 90_000);
    let start = Instant::now();
    let mut req = client
        .post(&url)
        .timeout(Duration::from_millis(effective_timeout))
        .header("Accept", "application/json")
        .json(&body);
    if !resolved_key.trim().is_empty() {
        req = req.bearer_auth(resolved_key.trim());
    }

    let mut resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let ms = start.elapsed().as_millis() as u64;
            let category = if e.is_timeout() { "timeout" } else { "network" };
            return ProbeOutcome {
                ok: false,
                category: category.to_string(),
                status_code: None,
                ms: Some(ms),
                at: now,
                text: Some(category.to_string()),
            };
        }
    };

    let ms = start.elapsed().as_millis() as u64;
    let code = resp.status().as_u16();
    if !resp.status().is_success() {
        let category = match code {
            401 | 403 => "auth",
            402 | 429 => "quota",
            404 => "model_not_found",
            400 | 422 => "request",
            c if c >= 500 => "upstream",
            _ => "http_error",
        };
        return ProbeOutcome {
            ok: false,
            category: category.to_string(),
            status_code: Some(code),
            ms: Some(ms),
            at: now,
            text: Some(format!("{} · HTTP {}", category, code)),
        };
    }

    let bytes = match read_bounded_bytes(&mut resp, CHAT_PROBE_RESPONSE_MAX_BYTES).await {
        Ok(b) => b,
        Err(cat) => {
            return ProbeOutcome {
                ok: false,
                category: cat.clone(),
                status_code: Some(code),
                ms: Some(ms),
                at: now,
                text: Some(format!("{} · HTTP {}", cat, code)),
            };
        }
    };

    let Ok(parsed) = serde_json::from_slice::<Value>(&bytes) else {
        return ProbeOutcome {
            ok: false,
            category: "decode_error".to_string(),
            status_code: Some(code),
            ms: Some(ms),
            at: now,
            text: Some(format!("decode_error · HTTP {}", code)),
        };
    };

    if is_chat_response_alive(&parsed) {
        ProbeOutcome {
            ok: true,
            category: "ok".to_string(),
            status_code: Some(code),
            ms: Some(ms),
            at: now,
            text: Some(format!("{} ms", ms)),
        }
    } else {
        ProbeOutcome {
            ok: false,
            category: "upstream".to_string(),
            status_code: Some(code),
            ms: Some(ms),
            at: now,
            text: Some(format!("empty_or_error_body · HTTP {}", code)),
        }
    }
}

pub fn summarize_benchmark_samples(model: &str, samples: &[ProbeOutcome]) -> BenchmarkModelSummary {
    let mut good: Vec<u64> = samples
        .iter()
        .filter_map(|s| if s.ok { s.ms } else { None })
        .collect();
    good.sort_unstable();

    let runs = samples.len();
    let ok_runs = good.len();
    let success_rate = if runs > 0 {
        ok_runs as f64 / runs as f64
    } else {
        0.0
    };

    let median_ms = good.get(good.len() / 2).copied();
    let p90_ms = if good.is_empty() {
        None
    } else {
        let rank = ((good.len() as f64) * 0.90).ceil() as usize;
        let idx = rank.saturating_sub(1).min(good.len() - 1);
        good.get(idx).copied()
    };
    let best_ms = good.first().copied();
    let worst_ms = good.last().copied();

    let mut error = String::new();
    let mut cats = HashSet::new();
    for s in samples.iter().filter(|s| !s.ok) {
        if !s.category.trim().is_empty() {
            cats.insert(s.category.clone());
        }
        if error.is_empty() {
            error = s
                .text
                .clone()
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| {
                    s.status_code
                        .map(|c| format!("{} · HTTP {}", s.category, c))
                        .unwrap_or_else(|| s.category.clone())
                });
        }
    }
    let mut categories: Vec<String> = cats.into_iter().collect();
    categories.sort();

    BenchmarkModelSummary {
        model: model.to_string(),
        runs,
        ok_runs,
        success_rate,
        median_ms,
        p90_ms,
        best_ms,
        worst_ms,
        error,
        categories,
    }
}

pub fn sort_benchmark_results(results: &mut [BenchmarkModelSummary]) {
    results.sort_by(|a, b| {
        let a_full = a.ok_runs == a.runs && a.runs > 0;
        let b_full = b.ok_runs == b.runs && b.runs > 0;
        b_full
            .cmp(&a_full)
            .then_with(|| b.ok_runs.cmp(&a.ok_runs))
            .then_with(|| a.median_ms.is_none().cmp(&b.median_ms.is_none()))
            .then_with(|| {
                a.median_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&b.median_ms.unwrap_or(u64::MAX))
            })
            .then_with(|| {
                a.model
                    .to_ascii_lowercase()
                    .cmp(&b.model.to_ascii_lowercase())
            })
    });
}

pub async fn run_provider_benchmark<F>(
    models: Vec<String>,
    rounds: usize,
    api_base: &str,
    resolved_key: &str,
    mut cancel_rx: watch::Receiver<bool>,
    mut on_progress: F,
) -> (Vec<BenchmarkModelSummary>, bool)
where
    F: FnMut(BenchmarkProgressEvent),
{
    let effective_rounds = rounds.clamp(1, MAX_BENCHMARK_ROUNDS);
    let mut seen = HashSet::new();
    let mut picked = Vec::new();
    for m in models {
        let trimmed = m.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_ascii_lowercase()) {
            picked.push(trimmed);
            if picked.len() >= MAX_BENCHMARK_MODELS {
                break;
            }
        }
    }

    let total_models = picked.len();
    on_progress(BenchmarkProgressEvent::Started {
        total_models,
        rounds: effective_rounds,
    });

    if total_models == 0 {
        on_progress(BenchmarkProgressEvent::Completed {
            cancelled: false,
            results: Vec::new(),
        });
        return (Vec::new(), false);
    }

    let mut results = Vec::with_capacity(total_models);
    for (idx, model) in picked.iter().enumerate() {
        let mut samples = Vec::with_capacity(effective_rounds);
        for _ in 0..effective_rounds {
            if *cancel_rx.borrow() {
                on_progress(BenchmarkProgressEvent::Completed {
                    cancelled: true,
                    results: results.clone(),
                });
                return (results, true);
            }
            let outcome = tokio::select! {
                _ = cancel_rx.wait_for(|v| *v) => {
                    on_progress(BenchmarkProgressEvent::Completed {
                        cancelled: true,
                        results: results.clone(),
                    });
                    return (results, true);
                }
                res = probe_chat_model(model, api_base, resolved_key, DEFAULT_PROBE_TIMEOUT_MS) => res,
            };
            samples.push(outcome);
        }
        let summary = summarize_benchmark_samples(model, &samples);
        results.push(summary.clone());
        on_progress(BenchmarkProgressEvent::ModelDone {
            completed: idx + 1,
            total_models,
            summary,
        });
    }

    sort_benchmark_results(&mut results);
    on_progress(BenchmarkProgressEvent::Completed {
        cancelled: false,
        results: results.clone(),
    });
    (results, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_parse_model_ids_dedupes_case_insensitively_and_supports_models_array() {
        let openai = json!({
            "data": [
                {"id": "gpt-5.2"},
                {"id": "GPT-5.2"},
                {"id": "claude-opus-4"},
                "  gemini-3.8-flash  ",
                {"id": "bad\nmodel"}
            ]
        });
        assert_eq!(
            parse_model_ids_from_body(&openai),
            vec!["gpt-5.2", "claude-opus-4", "gemini-3.8-flash"]
        );

        let alt = json!({
            "models": [{"name": "qwen3-coder"}, {"id": "deepseek-v4"}]
        });
        assert_eq!(
            parse_model_ids_from_body(&alt),
            vec!["qwen3-coder", "deepseek-v4"]
        );
    }

    #[test]
    fn test_summarize_and_sort_benchmark_results() {
        let fast = summarize_benchmark_samples(
            "m-fast",
            &[
                ProbeOutcome {
                    ok: true,
                    category: "ok".to_string(),
                    status_code: Some(200),
                    ms: Some(180),
                    at: 1.0,
                    text: None,
                },
                ProbeOutcome {
                    ok: true,
                    category: "ok".to_string(),
                    status_code: Some(200),
                    ms: Some(120),
                    at: 2.0,
                    text: None,
                },
                ProbeOutcome {
                    ok: true,
                    category: "ok".to_string(),
                    status_code: Some(200),
                    ms: Some(300),
                    at: 3.0,
                    text: None,
                },
            ],
        );
        assert_eq!(fast.ok_runs, 3);
        assert_eq!(fast.best_ms, Some(120));
        assert_eq!(fast.median_ms, Some(180));
        assert_eq!(fast.p90_ms, Some(300));
        assert_eq!(fast.worst_ms, Some(300));

        let partial = summarize_benchmark_samples(
            "a-partial",
            &[
                ProbeOutcome {
                    ok: true,
                    category: "ok".to_string(),
                    status_code: Some(200),
                    ms: Some(80),
                    at: 1.0,
                    text: None,
                },
                ProbeOutcome {
                    ok: false,
                    category: "quota".to_string(),
                    status_code: Some(429),
                    ms: Some(40),
                    at: 2.0,
                    text: Some("quota · HTTP 429".to_string()),
                },
            ],
        );
        assert_eq!(partial.ok_runs, 1);
        assert_eq!(partial.error, "quota · HTTP 429");

        let mut rows = vec![partial, fast];
        sort_benchmark_results(&mut rows);
        assert_eq!(rows[0].model, "m-fast");
        assert_eq!(rows[1].model, "a-partial");
    }

    #[tokio::test]
    async fn test_list_models_and_probe_chat_mock_server_and_redacts_secrets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}/v1", port);

        tokio::spawn(async move {
            for _ in 0..5 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = req_str.lines().next().unwrap_or("");
                    let lower = req_str.to_ascii_lowercase();
                    let authed = lower.contains("authorization: bearer synthetic_key_abc");

                    let (status_line, body) = if !authed {
                        (
                            "HTTP/1.1 401 Unauthorized",
                            r#"{"error":"invalid api_key=SYNTHETIC_BAD_999"}"#,
                        )
                    } else if first_line.starts_with("GET /v1/models ") {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"data":[{"id":"m-fast"},{"id":"m-fake200"}]}"#,
                        )
                    } else if req_str.contains("\"m-fake200\"") {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"error":{"message":"upstream down"}}"#,
                        )
                    } else if req_str.contains("\"m-429\"") {
                        (
                            "HTTP/1.1 429 Too Many Requests",
                            r#"{"error":"rate limit"}"#,
                        )
                    } else {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"choices":[{"finish_reason":"stop","message":{"content":"OK"}}]}"#,
                        )
                    };
                    let resp = format!(
                        "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status_line,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        let denied = list_provider_models(&base_url, "SYNTHETIC_BAD_999").await;
        assert!(!denied.ok);
        assert_eq!(denied.status_code, Some(401));
        assert!(!denied.error.contains("SYNTHETIC_BAD_999"));

        let listed = list_provider_models(&base_url, "SYNTHETIC_KEY_ABC").await;
        assert!(listed.ok);
        assert_eq!(listed.ids, vec!["m-fast", "m-fake200"]);

        let ok_probe = probe_chat_model("m-fast", &base_url, "SYNTHETIC_KEY_ABC", 5_000).await;
        assert!(ok_probe.ok);
        assert_eq!(ok_probe.category, "ok");

        let fake_200 = probe_chat_model("m-fake200", &base_url, "SYNTHETIC_KEY_ABC", 5_000).await;
        assert!(!fake_200.ok);
        assert_eq!(fake_200.category, "upstream");

        let quota = probe_chat_model("m-429", &base_url, "SYNTHETIC_KEY_ABC", 5_000).await;
        assert!(!quota.ok);
        assert_eq!(quota.category, "quota");
        assert_eq!(quota.status_code, Some(429));
    }

    #[tokio::test]
    async fn test_run_provider_benchmark_cancels_promptly() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{}/v1", port);

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        let (cancel_tx, cancel_rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let _ = cancel_tx.send(true);
        });

        let start = Instant::now();
        let (_results, cancelled) = run_provider_benchmark(
            vec!["slow-model".to_string()],
            2,
            &base_url,
            "SYNTHETIC_KEY",
            cancel_rx,
            |_| {},
        )
        .await;
        assert!(cancelled);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
