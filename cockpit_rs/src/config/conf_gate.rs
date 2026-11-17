//! Configuration gate and slot manager for OpenViking ov.conf.
//!
//! Features:
//! - Loads ov.conf without expanding environment variables into memory, preventing write-back leakage.
//! - Creates mandatory verified pre-write backups (`backups/ov.conf-before-...`).
//! - Restricts access control list (DACL) on backup and live files.
//! - Enforces atomic file replacement and SHA-256 integrity verification.
//! - Strict safety guard: Hardcoded protection preventing any unit test from writing to live ov.conf.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::safe_write::{
    apply_restricted_file_acl, safe_atomic_write_text, sha256_hex, SafeWriteError,
};

#[derive(Debug, thiserror::Error)]
pub enum ConfGateError {
    #[error("Safe write error: {0}")]
    SafeWrite(#[from] SafeWriteError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration validation error: {0}")]
    Validation(String),

    #[error("Revision mismatch for {file}: expected {expected}, found {actual}")]
    RevisionMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("Refusing to modify live configuration: {0}")]
    LivePathProtected(String),
}

/// OpenViking configuration root structure (lenient serde with stable key ordering).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenVikingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlm: Option<VlmConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// VLM section configuration.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VlmConfig {
    pub model: String,
    pub api_base: String,
    pub api_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failback_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failback_request_count: Option<u32>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

// Custom Debug implementation to prevent sensitive keys from leaking into loggers
impl fmt::Debug for VlmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlmConfig")
            .field("model", &self.model)
            .field("api_base", &self.api_base)
            .field("api_key", &"[REDACTED]")
            .field("thinking", &self.thinking)
            .field("max_retries", &self.max_retries)
            .field("failback_timeout_seconds", &self.failback_timeout_seconds)
            .field("failback_request_count", &self.failback_request_count)
            .field("extra", &self.extra)
            .finish()
    }
}

/// Checks destination path against the operator's live ov.conf to prevent unit tests or accidental writes.
pub fn verify_not_live_path(dest_path: &Path) -> Result<(), ConfGateError> {
    let home_var = std::env::var_os("USERPROFILE");
    let home_path = home_var.as_ref().map(Path::new);
    let allow_live = std::env::var("COCKPIT_ALLOW_LIVE_WRITE").as_deref() == Ok("1");
    if super::safe_write::is_live_path_protected(dest_path, home_path, allow_live) {
        return Err(ConfGateError::LivePathProtected(
            dest_path.display().to_string(),
        ));
    }
    Ok(())
}

/// Reads configuration file from disk as raw text and parses without variable expansion.
/// Strips UTF-8 Byte Order Mark (BOM) if present before JSON deserialization.
pub fn load_raw_config(path: &Path) -> Result<(OpenVikingConfig, String, String), ConfGateError> {
    let raw_text = fs::read_to_string(path)?;
    let sha = sha256_hex(raw_text.as_bytes());
    let clean_json = raw_text.strip_prefix('\u{feff}').unwrap_or(&raw_text);
    let parsed: OpenVikingConfig = serde_json::from_str(clean_json)?;
    Ok((parsed, raw_text, sha))
}

/// Creates a mandatory pre-write backup in the designated backup directory.
/// Writes raw bytes directly and verifies the written backup's SHA-256 matches the source.
/// Format: `ov.conf-before-<epoch_seconds>Z-<hash_prefix>.bak`
pub fn create_pre_write_backup(
    conf_path: &Path,
    backups_dir: &Path,
) -> Result<PathBuf, ConfGateError> {
    if !conf_path.is_file() {
        return Err(ConfGateError::Validation(format!(
            "Cannot create backup: source file {} does not exist",
            conf_path.display()
        )));
    }

    fs::create_dir_all(backups_dir)?;

    let raw_bytes = fs::read(conf_path)?;
    let sha = sha256_hex(&raw_bytes);
    let hash_prefix = &sha[..8];

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let backup_filename = format!("ov.conf-before-{}Z-{}.bak", now_secs, hash_prefix);
    let backup_path = backups_dir.join(backup_filename);

    // Write raw bytes directly for byte-exact fidelity
    fs::write(&backup_path, &raw_bytes)?;
    apply_restricted_file_acl(&backup_path)?;

    // Verify backup byte fidelity
    let backup_readback = fs::read(&backup_path)?;
    let backup_sha = sha256_hex(&backup_readback);
    if backup_sha != sha {
        let _ = fs::remove_file(&backup_path);
        return Err(ConfGateError::Validation(format!(
            "Backup integrity check failed: written SHA {} != source SHA {}",
            backup_sha, sha
        )));
    }

    Ok(backup_path)
}

/// Atomically saves configuration to `dest_path` after creating a verified backup.
pub fn save_config_with_backup(
    dest_path: &Path,
    backups_dir: &Path,
    config: &OpenVikingConfig,
    expected_previous_sha: Option<&str>,
) -> Result<(String, Option<PathBuf>), ConfGateError> {
    // 1. Guard against accidental writes to live path
    verify_not_live_path(dest_path)?;

    // 2. Validate mandatory fields before touching filesystem
    if let Some(ref vlm) = config.vlm {
        if vlm.model.trim().is_empty() {
            return Err(ConfGateError::Validation(
                "VLM model cannot be empty".to_string(),
            ));
        }
        if vlm.api_base.trim().is_empty() {
            return Err(ConfGateError::Validation(
                "VLM api_base cannot be empty".to_string(),
            ));
        }
    }

    // 3. Revision check before backup creation (prevent failed revisions from littering backups/)
    if let Some(expected_sha) = expected_previous_sha {
        if dest_path.is_file() {
            let current_bytes = fs::read(dest_path)?;
            let current_sha = sha256_hex(&current_bytes);
            if current_sha != expected_sha {
                return Err(ConfGateError::RevisionMismatch {
                    file: dest_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    expected: expected_sha.to_string(),
                    actual: current_sha,
                });
            }
        }
    }

    // 4. Create pre-write backup if destination file exists
    let backup_path = if dest_path.is_file() {
        Some(create_pre_write_backup(dest_path, backups_dir)?)
    } else {
        None
    };

    // 5. Serialize to formatted JSON with trailing newline
    let payload = serde_json::to_string_pretty(config)? + "\n";

    // 6. Safe atomic write with revision check
    let written_sha = safe_atomic_write_text(dest_path, &payload, true, expected_previous_sha)?;

    // 7. Post-write schema validation (compare full reloaded struct)
    let (reloaded, _, _) = load_raw_config(dest_path)?;
    if reloaded != *config {
        // Rollback from verified backup if available
        if let Some(ref bak) = backup_path {
            if let Ok(bak_bytes) = fs::read(bak) {
                let _ = safe_atomic_write_text(
                    dest_path,
                    &String::from_utf8_lossy(&bak_bytes),
                    true,
                    None,
                );
            }
        }
        return Err(ConfGateError::Validation(
            "Post-write verification failed: reloaded configuration does not match source struct"
                .to_string(),
        ));
    }

    Ok((written_sha, backup_path))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_and_save_without_env_expansion() {
        let dir = tempdir().expect("create tempdir");
        let conf_path = dir.path().join("ov.conf");
        let backups_dir = dir.path().join("backups");

        // Write initial config with environment variable placeholders
        let initial_json = r#"{
  "vlm": {
    "model": "qwen2.5-vl-7b-instruct",
    "api_base": "https://api.example.com/v1",
    "api_key": "${MY_SECRET_KEY_VAR}",
    "thinking": true
  },
  "embedding": {
    "dense": {
      "model": "qwen3-embedding:0.6b"
    }
  }
}
"#;
        fs::write(&conf_path, initial_json).expect("write initial ov.conf");

        // 1. Load config and verify raw placeholders are intact
        let (mut cfg, _, sha1) = load_raw_config(&conf_path).expect("load config");
        assert_eq!(
            cfg.vlm.as_ref().unwrap().api_key,
            "${MY_SECRET_KEY_VAR}",
            "Environment variable placeholder was corrupted or expanded!"
        );

        // 2. Modify model name while preserving ${MY_SECRET_KEY_VAR}
        cfg.vlm.as_mut().unwrap().model = "qwen2.5-vl-72b-instruct".to_string();

        let (sha2, backup_path) =
            save_config_with_backup(&conf_path, &backups_dir, &cfg, Some(&sha1))
                .expect("save config");

        assert_ne!(sha1, sha2);
        assert!(backup_path.is_some());
        assert!(backup_path.unwrap().is_file());

        // 3. Reload from disk and verify ${MY_SECRET_KEY_VAR} was written verbatim without leaking
        let (reloaded, reloaded_text, _) = load_raw_config(&conf_path).expect("reload config");
        assert_eq!(
            reloaded.vlm.as_ref().unwrap().api_key,
            "${MY_SECRET_KEY_VAR}",
            "Write-back leaked or altered variable syntax!"
        );
        assert!(
            reloaded_text.contains("\"${MY_SECRET_KEY_VAR}\""),
            "Raw JSON does not contain exact placeholder string!"
        );
    }

    #[test]
    fn test_save_empty_model_fails_closed() {
        let dir = tempdir().expect("create tempdir");
        let conf_path = dir.path().join("ov.conf");
        let backups_dir = dir.path().join("backups");

        let bad_cfg = OpenVikingConfig {
            vlm: Some(VlmConfig {
                model: "   ".to_string(),
                api_base: "https://api.example.com".to_string(),
                api_key: "key".to_string(),
                thinking: None,
                max_retries: None,
                failback_timeout_seconds: None,
                failback_request_count: None,
                extra: Default::default(),
            }),
            embedding: None,
            extra: Default::default(),
        };

        let res = save_config_with_backup(&conf_path, &backups_dir, &bad_cfg, None);
        assert!(matches!(res, Err(ConfGateError::Validation(_))));
        assert!(!conf_path.exists());
    }

    #[test]
    fn test_load_and_save_with_utf8_bom() {
        let dir = tempdir().expect("create tempdir");
        let conf_path = dir.path().join("ov.conf");
        let backups_dir = dir.path().join("backups");

        // Write initial config with UTF-8 BOM (\u{FEFF} / [0xEF, 0xBB, 0xBF])
        let bom_json = "\u{feff}{\n  \"vlm\": {\n    \"model\": \"qwen2.5-vl-7b-instruct\",\n    \"api_base\": \"https://api.example.com/v1\",\n    \"api_key\": \"${MY_KEY}\"\n  }\n}\n";
        fs::write(&conf_path, bom_json.as_bytes()).expect("write bom ov.conf");

        // 1. Verify load_raw_config handles BOM without error
        let (cfg, raw, sha1) = load_raw_config(&conf_path).expect("load bom config");
        assert_eq!(cfg.vlm.as_ref().unwrap().model, "qwen2.5-vl-7b-instruct");
        assert_eq!(sha1, sha256_hex(bom_json.as_bytes()));
        assert!(raw.starts_with('\u{feff}'));

        // 2. Verify save_config_with_backup creates verified backup matching BOM bytes
        let (sha2, backup_path) =
            save_config_with_backup(&conf_path, &backups_dir, &cfg, Some(&sha1))
                .expect("save config with bom backup");

        assert_ne!(sha1, sha2);
        let backup = backup_path.expect("backup created");
        let backup_bytes = fs::read(backup).expect("read backup");
        assert_eq!(
            sha256_hex(&backup_bytes),
            sha1,
            "Backup failed to preserve exact BOM bytes!"
        );
        assert!(
            backup_bytes.starts_with(&[0xef, 0xbb, 0xbf]),
            "Backup missing original BOM bytes!"
        );

        // 3. Verify newly written file is clean valid JSON without BOM pollution
        let (reloaded, reloaded_text, sha_reloaded) =
            load_raw_config(&conf_path).expect("reload config");
        assert_eq!(sha_reloaded, sha2);
        assert!(
            !reloaded_text.starts_with('\u{feff}'),
            "Newly written config should be clean standard UTF-8 without BOM!"
        );
        assert_eq!(
            reloaded.vlm.as_ref().unwrap().api_key,
            "${MY_KEY}",
            "Environment variable was altered or leaked!"
        );
    }
}
