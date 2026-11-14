//! Secure secret storage for OpenViking Cockpit on Windows 11.
//!
//! Provides:
//! - 64-bit safe native Windows DPAPI encryption via windows-sys.
//! - Fail-loud error handling (never returns ciphertext as key, never returns empty string on decrypt error).
//! - Typed resolution status: SecretReady, DpapiUnavailable, MissingEnvironmentVariable,
//!   EmptyEnvironmentVariable, InvalidSecretReference, EmptySecret.
//! - Strict environment variable reference parser: `^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$` (full-string only).
//! - Security invariant: manual Debug implementation redacts value to `[REDACTED]`.
//! - Security invariant: never echoes raw secret strings into error messages.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretStatus {
    SecretReady,
    DpapiUnavailable,
    MissingEnvironmentVariable,
    EmptyEnvironmentVariable,
    InvalidSecretReference,
    EmptySecret,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSecret {
    pub status: SecretStatus,
    #[serde(default, skip_serializing)]
    pub value: String,
    pub error_message: Option<String>,
    pub env_var_name: Option<String>,
}

// Security invariant: never print the plaintext secret value in debug logs
impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedSecret")
            .field("status", &self.status)
            .field("value", &"[REDACTED]")
            .field("error_message", &self.error_message)
            .field("env_var_name", &self.env_var_name)
            .finish()
    }
}

impl ResolvedSecret {
    pub fn new(status: SecretStatus, value: impl Into<String>) -> Self {
        Self {
            status,
            value: value.into(),
            error_message: None,
            env_var_name: None,
        }
    }

    pub fn with_error(status: SecretStatus, msg: impl Into<String>) -> Self {
        Self {
            status,
            value: String::new(),
            error_message: Some(msg.into()),
            env_var_name: None,
        }
    }

    pub fn with_env_var(
        status: SecretStatus,
        value: impl Into<String>,
        env_name: impl Into<String>,
    ) -> Self {
        Self {
            status,
            value: value.into(),
            error_message: None,
            env_var_name: Some(env_name.into()),
        }
    }

    pub fn with_env_error(
        status: SecretStatus,
        msg: impl Into<String>,
        env_name: impl Into<String>,
    ) -> Self {
        Self {
            status,
            value: String::new(),
            error_message: Some(msg.into()),
            env_var_name: Some(env_name.into()),
        }
    }
}

static ENV_REF_REGEX: OnceLock<Regex> = OnceLock::new();
static MALFORMED_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_env_ref_regex() -> &'static Regex {
    ENV_REF_REGEX.get_or_init(|| Regex::new(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$").unwrap())
}

fn get_malformed_regex() -> &'static Regex {
    MALFORMED_REGEX.get_or_init(|| {
        Regex::new(r"^(?:\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|Bearer\s+\$\{[A-Za-z0-9_]+\}|\$\{.*[^\}\s])$").unwrap()
    })
}

pub fn is_env_ref(text: &str) -> bool {
    let trimmed = text.trim();
    get_env_ref_regex().is_match(trimmed)
}

pub fn get_env_var_name(text: &str) -> Option<String> {
    let trimmed = text.trim();
    get_env_ref_regex()
        .captures(trimmed)
        .map(|c| c[1].to_string())
}

#[cfg(windows)]
mod win32 {
    use super::{ResolvedSecret, SecretStatus};
    use base64::Engine;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    struct LocalFreeGuard(*mut u8);
    impl Drop for LocalFreeGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0 as _) };
            }
        }
    }

    pub fn dpapi_protect(text: &str, description: Option<&str>) -> Result<String, String> {
        if text.is_empty() {
            return Ok(String::new());
        }
        if text.starts_with("dpapi:") {
            return Ok(text.to_string());
        }
        let bytes = text.as_bytes();
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        let desc_wide: Option<Vec<u16>> =
            description.map(|d| d.encode_utf16().chain(Some(0)).collect());
        let desc_ptr = desc_wide.as_ref().map(|w| w.as_ptr()).unwrap_or(null_mut());

        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                desc_ptr,
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!("CryptProtectData failed with error code: {}", err));
        }
        let _guard = LocalFreeGuard(out_blob.pbData);
        let slice =
            unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
        let b64 = base64::engine::general_purpose::STANDARD.encode(slice);
        Ok(format!("dpapi:{}", b64))
    }

    pub fn dpapi_unprotect_strict(cipher: &str) -> ResolvedSecret {
        let trimmed = cipher.trim();
        if trimmed.is_empty() {
            return ResolvedSecret::new(SecretStatus::EmptySecret, "");
        }
        if !trimmed.starts_with("dpapi:") {
            return ResolvedSecret::new(SecretStatus::SecretReady, trimmed);
        }

        let raw_b64 = &trimmed[6..];
        let raw = match base64::engine::general_purpose::STANDARD.decode(raw_b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                return ResolvedSecret::with_error(
                    SecretStatus::DpapiUnavailable,
                    format!("Base64 decode failed: {}", e),
                );
            }
        };

        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: raw.len() as u32,
            pbData: raw.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return ResolvedSecret::with_error(
                SecretStatus::DpapiUnavailable,
                format!("CryptUnprotectData failed with error code: {}", err),
            );
        }

        let _guard = LocalFreeGuard(out_blob.pbData);
        let slice =
            unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
        let owned_str = match std::str::from_utf8(slice) {
            Ok(s) => s.to_string(),
            Err(e) => {
                return ResolvedSecret::with_error(
                    SecretStatus::DpapiUnavailable,
                    format!("UTF-8 decode failed: {}", e),
                );
            }
        };

        // Explicitly release Win32 buffer immediately after cloning into owned String
        drop(_guard);

        if owned_str.starts_with("dpapi:") {
            return ResolvedSecret::with_error(
                SecretStatus::DpapiUnavailable,
                "Decrypted payload returned another dpapi: envelope (corrupted payload)",
            );
        }

        ResolvedSecret::new(SecretStatus::SecretReady, owned_str)
    }
}

#[cfg(not(windows))]
mod non_windows {
    use super::{ResolvedSecret, SecretStatus};

    pub fn dpapi_protect(_text: &str, _description: Option<&str>) -> Result<String, String> {
        Err("DPAPI is only supported on Windows".to_string())
    }

    pub fn dpapi_unprotect_strict(cipher: &str) -> ResolvedSecret {
        let trimmed = cipher.trim();
        if trimmed.is_empty() {
            return ResolvedSecret::new(SecretStatus::EmptySecret, "");
        }
        if !trimmed.starts_with("dpapi:") {
            return ResolvedSecret::new(SecretStatus::SecretReady, trimmed);
        }
        ResolvedSecret::with_error(
            SecretStatus::DpapiUnavailable,
            "DPAPI is only supported on Windows",
        )
    }
}

#[cfg(windows)]
pub use win32::*;

#[cfg(not(windows))]
pub use non_windows::*;

pub fn resolve_secret(
    secret_raw: &str,
    env_map: Option<&HashMap<String, String>>,
) -> ResolvedSecret {
    let text = secret_raw.trim();
    if text.is_empty() {
        return ResolvedSecret::new(SecretStatus::EmptySecret, "");
    }

    // 1. Check if DPAPI
    if text.starts_with("dpapi:") {
        return dpapi_unprotect_strict(text);
    }

    // 2. Check if Environment Reference ${NAME}
    if let Some(captures) = get_env_ref_regex().captures(text) {
        let var_name = captures[1].to_string();
        let val_opt = match env_map {
            Some(map) => map.get(&var_name).cloned(),
            None => std::env::var(&var_name).ok(),
        };

        let val = match val_opt {
            Some(v) => v,
            None => {
                return ResolvedSecret::with_env_error(
                    SecretStatus::MissingEnvironmentVariable,
                    format!(
                        "Environment variable '{}' is not set in process environment",
                        var_name
                    ),
                    var_name,
                );
            }
        };

        let trimmed_val = val.trim();
        if trimmed_val.is_empty() {
            return ResolvedSecret::with_env_error(
                SecretStatus::EmptyEnvironmentVariable,
                format!("Environment variable '{}' is empty", var_name),
                var_name,
            );
        }

        if trimmed_val.starts_with("dpapi:") {
            return ResolvedSecret::with_env_error(
                SecretStatus::InvalidSecretReference,
                format!(
                    "Environment variable '{}' resolved to raw dpapi cipher, not allowed",
                    var_name
                ),
                var_name,
            );
        }

        return ResolvedSecret::with_env_var(SecretStatus::SecretReady, trimmed_val, var_name);
    }

    // 3. Check for malformed syntax
    // Security invariant: DO NOT leak the raw user secret string into the error message
    if text.contains("${")
        || text.starts_with('$')
        || text.starts_with('%')
        || text.starts_with("Bearer $")
        || text.starts_with("Bearer %")
        || get_malformed_regex().is_match(text)
    {
        return ResolvedSecret::with_error(
            SecretStatus::InvalidSecretReference,
            "Malformed environment variable reference. Strict syntax requires entire string to be '${NAME}'",
        );
    }

    // 4. Plaintext passthrough
    ResolvedSecret::new(SecretStatus::SecretReady, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_secret() {
        assert_eq!(resolve_secret("", None).status, SecretStatus::EmptySecret);
        assert_eq!(
            resolve_secret("   ", None).status,
            SecretStatus::EmptySecret
        );
    }

    #[test]
    fn test_plaintext_passthrough() {
        let res = resolve_secret("TEST_SYNTHETIC_API_KEY_12345", None);
        assert_eq!(res.status, SecretStatus::SecretReady);
        assert_eq!(res.value, "TEST_SYNTHETIC_API_KEY_12345");
    }

    #[test]
    fn test_env_var_resolution() {
        let mut env = HashMap::new();
        env.insert(
            "MOCK_API_KEY".to_string(),
            "TEST_SYNTHETIC_API_KEY_12345".to_string(),
        );
        env.insert("EMPTY_KEY".to_string(), "   ".to_string());
        env.insert("NESTED_DPAPI".to_string(), "dpapi:AQAA...".to_string());

        // Valid
        let res1 = resolve_secret("${MOCK_API_KEY}", Some(&env));
        assert_eq!(res1.status, SecretStatus::SecretReady);
        assert_eq!(res1.value, "TEST_SYNTHETIC_API_KEY_12345");
        assert_eq!(res1.env_var_name.as_deref(), Some("MOCK_API_KEY"));

        // Missing
        let res2 = resolve_secret("${NON_EXISTENT_VAR}", Some(&env));
        assert_eq!(res2.status, SecretStatus::MissingEnvironmentVariable);

        // Empty
        let res3 = resolve_secret("${EMPTY_KEY}", Some(&env));
        assert_eq!(res3.status, SecretStatus::EmptyEnvironmentVariable);

        // Nested DPAPI in env
        let res4 = resolve_secret("${NESTED_DPAPI}", Some(&env));
        assert_eq!(res4.status, SecretStatus::InvalidSecretReference);
    }

    #[test]
    fn test_malformed_env_syntax_no_secret_leak() {
        let malformed_inputs = [
            "${UNCLOSED_VAR",
            "$RAW_VAR",
            "%WINDOWS_VAR%",
            "Bearer ${AUTH_TOKEN}",
            "prefix_${VAR}_suffix",
        ];

        for input in malformed_inputs {
            let res = resolve_secret(input, None);
            assert_eq!(
                res.status,
                SecretStatus::InvalidSecretReference,
                "failed for: {}",
                input
            );
            let err = res.error_message.unwrap_or_default();
            assert!(!err.contains(input), "Error leaked raw input: {}", err);
        }
    }

    #[test]
    fn test_debug_redaction_invariant() {
        let secret = ResolvedSecret::new(SecretStatus::SecretReady, "SUPER_CONFIDENTIAL_KEY_999");
        let debug_str = format!("{:?}", secret);
        assert!(
            !debug_str.contains("SUPER_CONFIDENTIAL_KEY_999"),
            "Debug leaked secret value!"
        );
        assert!(
            debug_str.contains("[REDACTED]"),
            "Debug missing [REDACTED] placeholder!"
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_dpapi_protect_and_unprotect_roundtrip() {
        let original = "TEST_SYNTHETIC_API_KEY_12345";
        let protected =
            dpapi_protect(original, Some("OpenViking DPAPI")).expect("dpapi_protect failed");
        assert!(
            protected.starts_with("dpapi:"),
            "ciphertext missing dpapi: prefix"
        );

        let resolved = dpapi_unprotect_strict(&protected);
        assert_eq!(resolved.status, SecretStatus::SecretReady);
        assert_eq!(resolved.value, original);

        // Resolve through resolve_secret
        let via_resolve = resolve_secret(&protected, None);
        assert_eq!(via_resolve.status, SecretStatus::SecretReady);
        assert_eq!(via_resolve.value, original);
    }

    #[cfg(windows)]
    #[test]
    fn test_dpapi_corrupted_base64() {
        let res = dpapi_unprotect_strict("dpapi:!!!not-valid-base64!!!");
        assert_eq!(res.status, SecretStatus::DpapiUnavailable);
        assert!(res.value.is_empty());
        assert!(res.error_message.unwrap().contains("Base64 decode failed"));
    }
}
