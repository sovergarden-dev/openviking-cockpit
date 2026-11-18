//! Read-only local storage and peer namespace inspector for OpenViking (`data-qwen06b` & `backups/quarantine`).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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
pub struct StorageFootprint {
    pub data_dir_name: String,
    pub vectordb: DirFootprint,
    pub memories_default: MemoriesFootprint,
    pub peers: Vec<PeerStorageStat>,
    pub sessions: SessionsStorageStat,
    pub quarantine: DirFootprint,
    pub logs: DirFootprint,
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

/// Computes a bounded, read-only local disk breakdown without traversing `backups/pre-*` recovery archives.
pub fn inspect_storage_footprint(ov_home: &Path) -> StorageFootprint {
    let quarantine = scan_dir_recursive(&ov_home.join("backups").join("quarantine"));
    let logs = scan_dir_recursive(&ov_home.join("logs"));

    let Some(data_dir) = resolve_active_data_dir(ov_home) else {
        return StorageFootprint {
            data_dir_name: String::new(),
            vectordb: DirFootprint::default(),
            memories_default: MemoriesFootprint::default(),
            peers: Vec::new(),
            sessions: SessionsStorageStat::default(),
            quarantine,
            logs,
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
                if lower.starts_with("cron_") || lower.starts_with("cron-") {
                    sessions.cron_sessions += 1;
                } else if lower.starts_with("hermes") {
                    sessions.hermes_sessions += 1;
                }
                let sub = scan_dir_recursive(&path);
                sessions.files += sub.files;
                sessions.bytes = sessions.bytes.saturating_add(sub.bytes);
            } else if meta.is_file() {
                sessions.files += 1;
                sessions.bytes = sessions.bytes.saturating_add(meta.len());
            }
        }
    }

    StorageFootprint {
        data_dir_name,
        vectordb,
        memories_default,
        peers,
        sessions,
        quarantine,
        logs,
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
    }
}
