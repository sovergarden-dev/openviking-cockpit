//! Read-only local storage and peer namespace inspector for OpenViking (`data-qwen06b` & `backups/quarantine`).

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::conf_gate::display_clean_path;
use crate::services::auditor_cache::presentation_sanitize_text;

pub const LOG_TAIL_MAX_READ_BYTES: u64 = 262_144;
pub const STALE_CRON_MIN_AGE_SECS: u64 = 7 * 86_400;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirFootprint {
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoriesFootprint {
    pub md_files: usize,
    pub sidecar_files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStorageStat {
    pub peer_id: String,
    pub display_label: String,
    pub md_files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionsStorageStat {
    pub total_sessions: usize,
    pub cron_sessions: usize,
    pub hermes_sessions: usize,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HygieneDryRunSummary {
    pub quarantine_files: usize,
    pub quarantine_bytes: u64,
    pub monitor_scratch_files: usize,
    pub monitor_scratch_bytes: u64,
    pub stale_cron_sessions: usize,
    pub stale_cron_bytes: u64,
    pub monitor_state_snapshots: usize,
    pub total_reclaimable_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageFootprint {
    pub data_dir_name: String,
    pub vectordb: DirFootprint,
    pub memories_default: MemoriesFootprint,
    pub peers: Vec<PeerStorageStat>,
    pub sessions: SessionsStorageStat,
    pub quarantine: DirFootprint,
    pub logs: DirFootprint,
    #[serde(default)]
    pub hygiene: HygieneDryRunSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogTailOutcome {
    pub log_name: String,
    pub file_path: String,
    pub exists: bool,
    pub file_size_bytes: u64,
    pub truncated: bool,
    pub lines: Vec<String>,
}

#[cfg(windows)]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    meta.file_type().is_symlink() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(windows))]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

fn scan_dir_recursive(root: &Path) -> DirFootprint {
    let mut out = DirFootprint::default();
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        return out;
    };
    if is_reparse_point(&root_meta) || !root_meta.is_dir() {
        return out;
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if is_reparse_point(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                out.files += 1;
                out.bytes = out.bytes.saturating_add(meta.len());
            }
        }
    }
    out
}

fn scan_memories_dir(root: &Path) -> MemoriesFootprint {
    let mut out = MemoriesFootprint::default();
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        return out;
    };
    if is_reparse_point(&root_meta) || !root_meta.is_dir() {
        return out;
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if is_reparse_point(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                out.bytes = out.bytes.saturating_add(meta.len());
                let fname = entry.file_name();
                let name_str = fname.to_string_lossy();
                if name_str.starts_with('.') {
                    out.sidecar_files += 1;
                } else if name_str.ends_with(".md") {
                    out.md_files += 1;
                } else {
                    out.sidecar_files += 1;
                }
            }
        }
    }
    out
}

/// Formats long Windows SID-qualified peer folder names (`desktop.sid-S-1-5-...-950d1a71a454`) into concise labels.
pub fn format_peer_display_label(peer_id: &str) -> String {
    let trimmed = peer_id.trim();
    if let Some((prefix, rest)) = trimmed.split_once(".sid-") {
        let suffix = rest.rsplit('-').next().unwrap_or(rest);
        let short_suffix: String = suffix.chars().take(8).collect();
        return format!("{} ({})", prefix, short_suffix);
    }
    trimmed.to_string()
}

fn resolve_active_data_dir(ov_home: &Path) -> Option<std::path::PathBuf> {
    let preferred = ov_home.join("data-qwen06b");
    if preferred.is_dir() {
        return Some(preferred);
    }
    let entries = fs::read_dir(ov_home).ok()?;
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if is_reparse_point(&meta) || !meta.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("data") {
            candidates.push(path);
        }
    }
    candidates.sort();
    candidates.into_iter().next()
}

fn scan_dir_stats_and_latest_mtime(root: &Path) -> (DirFootprint, u64) {
    let mut out = DirFootprint::default();
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        return (out, 0);
    };
    if is_reparse_point(&root_meta) || !root_meta.is_dir() {
        return (out, 0);
    }
    let mtime_secs = |m: &fs::Metadata| -> u64 {
        m.modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };
    let mut latest = mtime_secs(&root_meta);

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if is_reparse_point(&meta) {
                continue;
            }
            latest = latest.max(mtime_secs(&meta));
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                out.files += 1;
                out.bytes = out.bytes.saturating_add(meta.len());
            }
        }
    }
    (out, latest)
}

fn scan_monitor_scratch(monitor_dir: &Path) -> (usize, u64) {
    let mut files = 0usize;
    let mut bytes = 0u64;
    let Ok(entries) = fs::read_dir(monitor_dir) else {
        return (0, 0);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if is_reparse_point(&meta) || !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('_') && (name.ends_with(".py") || name.ends_with(".json")) {
            files += 1;
            bytes = bytes.saturating_add(meta.len());
        }
    }
    (files, bytes)
}

fn count_monitor_state_snapshots(state_root: &Path) -> usize {
    let Ok(entries) = fs::read_dir(state_root) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                return false;
            };
            if is_reparse_point(&meta) || !meta.is_dir() {
                return false;
            }
            let name = entry.file_name();
            let s = name.to_string_lossy();
            s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
        })
        .count()
}

pub fn resolve_allowed_log_path(ov_home: &Path, log_name: &str) -> Result<PathBuf, String> {
    match log_name.trim() {
        "server.log" => Ok(ov_home.join("logs").join("server.log")),
        "ollama.log" => Ok(ov_home.join("logs").join("ollama.log")),
        "lifecycle.jsonl" => Ok(ov_home.join("logs").join("lifecycle.jsonl")),
        "monitor_app.log" => Ok(ov_home.join("monitor").join("app.log")),
        _ => Err(format!("Unsupported log file '{}'", log_name.trim())),
    }
}

/// Reads the sanitized trailing lines from one allowlisted log file (`<= 256 KiB` tail, no symlinks).
pub fn read_allowed_log_tail(
    ov_home: &Path,
    log_name: &str,
    max_lines: usize,
) -> Result<LogTailOutcome, String> {
    let path = resolve_allowed_log_path(ov_home, log_name)?;
    let display_path = display_clean_path(&path);
    let capped_lines = max_lines.clamp(50, 1000);

    let Ok(meta) = fs::symlink_metadata(&path) else {
        return Ok(LogTailOutcome {
            log_name: log_name.trim().to_string(),
            file_path: display_path,
            exists: false,
            file_size_bytes: 0,
            truncated: false,
            lines: Vec::new(),
        });
    };
    if is_reparse_point(&meta) || !meta.is_file() {
        return Err("Refusing non-regular or symlinked log file".to_string());
    }

    let len = meta.len();
    let truncated = len > LOG_TAIL_MAX_READ_BYTES;
    let mut file = fs::File::open(&path).map_err(|e| format!("Failed to open log: {}", e))?;
    if truncated {
        file.seek(SeekFrom::Start(len - LOG_TAIL_MAX_READ_BYTES))
            .map_err(|e| format!("Failed to seek log: {}", e))?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read log: {}", e))?;

    let lossy = String::from_utf8_lossy(&buf);
    let mut raw_lines: Vec<&str> = lossy.lines().collect();
    if truncated && !raw_lines.is_empty() {
        raw_lines.remove(0);
    }
    let start = raw_lines.len().saturating_sub(capped_lines);
    let lines = raw_lines[start..]
        .iter()
        .map(|ln| presentation_sanitize_text(ln, None))
        .collect();

    Ok(LogTailOutcome {
        log_name: log_name.trim().to_string(),
        file_path: display_path,
        exists: true,
        file_size_bytes: len,
        truncated,
        lines,
    })
}

/// Computes a bounded, read-only local disk breakdown without traversing `backups/pre-*` recovery archives.
pub fn inspect_storage_footprint(ov_home: &Path) -> StorageFootprint {
    let quarantine = scan_dir_recursive(&ov_home.join("backups").join("quarantine"));
    let logs = scan_dir_recursive(&ov_home.join("logs"));
    let (monitor_scratch_files, monitor_scratch_bytes) =
        scan_monitor_scratch(&ov_home.join("monitor"));
    let monitor_state_snapshots =
        count_monitor_state_snapshots(&ov_home.join("backups").join("monitor-state"));

    let mut base_hygiene = HygieneDryRunSummary {
        quarantine_files: quarantine.files,
        quarantine_bytes: quarantine.bytes,
        monitor_scratch_files,
        monitor_scratch_bytes,
        stale_cron_sessions: 0,
        stale_cron_bytes: 0,
        monitor_state_snapshots,
        total_reclaimable_bytes: quarantine.bytes.saturating_add(monitor_scratch_bytes),
    };

    let Some(data_dir) = resolve_active_data_dir(ov_home) else {
        return StorageFootprint {
            data_dir_name: String::new(),
            vectordb: DirFootprint::default(),
            memories_default: MemoriesFootprint::default(),
            peers: Vec::new(),
            sessions: SessionsStorageStat::default(),
            quarantine,
            logs,
            hygiene: base_hygiene,
        };
    };

    let data_dir_name = data_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let vectordb = scan_dir_recursive(&data_dir.join("vectordb"));

    let user_default = data_dir
        .join("viking")
        .join("default")
        .join("user")
        .join("default");
    let memories_default = scan_memories_dir(&user_default.join("memories"));

    let mut peers = Vec::new();
    let peers_dir = user_default.join("peers");
    if let Ok(entries) = fs::read_dir(&peers_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if is_reparse_point(&meta) || !meta.is_dir() {
                continue;
            }
            let peer_id = entry.file_name().to_string_lossy().to_string();
            let mem_stat = scan_memories_dir(&path.join("memories"));
            peers.push(PeerStorageStat {
                display_label: format_peer_display_label(&peer_id),
                peer_id,
                md_files: mem_stat.md_files,
                bytes: mem_stat.bytes,
            });
        }
    }
    peers.sort_by(|a, b| {
        b.md_files
            .cmp(&a.md_files)
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut sessions = SessionsStorageStat::default();
    let sessions_dir = user_default.join("sessions");
    if let Ok(entries) = fs::read_dir(&sessions_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if is_reparse_point(&meta) {
                continue;
            }
            if meta.is_dir() {
                sessions.total_sessions += 1;
                let lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                let is_cron = lower.starts_with("cron_") || lower.starts_with("cron-");
                if is_cron {
                    sessions.cron_sessions += 1;
                } else if lower.starts_with("hermes") {
                    sessions.hermes_sessions += 1;
                }
                let (sub, latest_mtime) = scan_dir_stats_and_latest_mtime(&path);
                sessions.files += sub.files;
                sessions.bytes = sessions.bytes.saturating_add(sub.bytes);
                if is_cron
                    && latest_mtime > 0
                    && now_secs.saturating_sub(latest_mtime) >= STALE_CRON_MIN_AGE_SECS
                {
                    base_hygiene.stale_cron_sessions += 1;
                    base_hygiene.stale_cron_bytes =
                        base_hygiene.stale_cron_bytes.saturating_add(sub.bytes);
                }
            } else if meta.is_file() {
                sessions.files += 1;
                sessions.bytes = sessions.bytes.saturating_add(meta.len());
            }
        }
    }
    base_hygiene.total_reclaimable_bytes = base_hygiene
        .total_reclaimable_bytes
        .saturating_add(base_hygiene.stale_cron_bytes);

    StorageFootprint {
        data_dir_name,
        vectordb,
        memories_default,
        peers,
        sessions,
        quarantine,
        logs,
        hygiene: base_hygiene,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_peer_display_label_shortens_windows_sid() {
        assert_eq!(
            format_peer_display_label(
                "desktop.sid-S-1-5-21-1585259706-71133602-3325104020-1001-950d1a71a454"
            ),
            "desktop (950d1a71)"
        );
        assert_eq!(format_peer_display_label("hermes"), "hermes");
        assert_eq!(format_peer_display_label("antigravity"), "antigravity");
    }

    #[test]
    fn test_inspect_storage_footprint_counts_memories_peers_sessions_and_quarantine() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ov = tmp.path();

        let vdb = ov.join("data-qwen06b").join("vectordb");
        fs::create_dir_all(&vdb).unwrap();
        fs::write(vdb.join("index.bin"), vec![0u8; 1024]).unwrap();

        let ud = ov
            .join("data-qwen06b")
            .join("viking")
            .join("default")
            .join("user")
            .join("default");
        let mem = ud.join("memories").join("preferences");
        fs::create_dir_all(&mem).unwrap();
        fs::write(mem.join("pref1.md"), "alpha").unwrap();
        fs::write(mem.join(".overview.md"), "ov").unwrap();

        let p_hermes = ud
            .join("peers")
            .join("hermes")
            .join("memories")
            .join("events");
        fs::create_dir_all(&p_hermes).unwrap();
        fs::write(p_hermes.join("ev1.md"), "event1").unwrap();
        fs::write(p_hermes.join("ev2.md"), "event2").unwrap();

        let p_agy = ud
            .join("peers")
            .join("antigravity")
            .join("memories")
            .join("patterns");
        fs::create_dir_all(&p_agy).unwrap();
        fs::write(p_agy.join("pat1.md"), "pattern1").unwrap();

        let s_cron = ud.join("sessions").join("cron_3db6_01");
        let s_hermes = ud.join("sessions").join("hermes-run-1");
        let s_user = ud.join("sessions").join("20261118_chat");
        for s in [&s_cron, &s_hermes, &s_user] {
            fs::create_dir_all(s).unwrap();
            fs::write(s.join("messages.jsonl"), "{}\n").unwrap();
        }

        let quar = ov.join("backups").join("quarantine");
        fs::create_dir_all(&quar).unwrap();
        fs::write(quar.join("stale.json"), vec![b'x'; 200]).unwrap();

        let snap = inspect_storage_footprint(ov);
        assert_eq!(snap.data_dir_name, "data-qwen06b");
        assert_eq!(snap.vectordb.files, 1);
        assert_eq!(snap.vectordb.bytes, 1024);
        assert_eq!(snap.memories_default.md_files, 1);
        assert_eq!(snap.memories_default.sidecar_files, 1);
        assert_eq!(snap.peers.len(), 2);
        assert_eq!(snap.peers[0].peer_id, "hermes");
        assert_eq!(snap.peers[0].md_files, 2);
        assert_eq!(snap.peers[1].peer_id, "antigravity");
        assert_eq!(snap.peers[1].md_files, 1);
        assert_eq!(snap.sessions.total_sessions, 3);
        assert_eq!(snap.sessions.cron_sessions, 1);
        assert_eq!(snap.sessions.hermes_sessions, 1);
        assert_eq!(snap.sessions.files, 3);
        assert_eq!(snap.quarantine.files, 1);
        assert_eq!(snap.quarantine.bytes, 200);
        assert_eq!(snap.hygiene.quarantine_files, 1);
        assert_eq!(snap.hygiene.quarantine_bytes, 200);

        let monitor_dir = ov.join("monitor");
        fs::create_dir_all(&monitor_dir).unwrap();
        fs::write(monitor_dir.join("_scratch_test.py"), vec![b'a'; 128]).unwrap();
        fs::write(monitor_dir.join("keep_me.json"), vec![b'b'; 64]).unwrap();

        let logs_dir = ov.join("logs");
        fs::create_dir_all(&logs_dir).unwrap();
        fs::write(
            logs_dir.join("server.log"),
            "INFO started\nERROR token=SYNTHETIC_LOG_SECRET_888 failed\nWARN slow\n",
        )
        .unwrap();

        let snap2 = inspect_storage_footprint(ov);
        assert_eq!(snap2.hygiene.monitor_scratch_files, 1);
        assert_eq!(snap2.hygiene.monitor_scratch_bytes, 128);
        assert_eq!(snap2.hygiene.total_reclaimable_bytes, 328);

        let tail = read_allowed_log_tail(ov, "server.log", 100).expect("read server log");
        assert!(tail.exists);
        assert_eq!(tail.lines.len(), 3);
        assert!(!tail.lines.join("\n").contains("SYNTHETIC_LOG_SECRET_888"));
        assert!(read_allowed_log_tail(ov, "../ov.conf", 100).is_err());
    }
}
