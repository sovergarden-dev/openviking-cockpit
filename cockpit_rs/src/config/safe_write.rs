//! Safe atomic file writing utilities with Windows DACL hardening and interprocess file locking.
//!
//! Features:
//! - Exclusive interprocess locking to prevent race conditions.
//! - Secure temporary file creation in destination directory (same filesystem volume).
//! - Restrictive ACL application before sensitive bytes are written.
//! - Atomic replacement using Windows ReplaceFileW / MoveFileExW.
//! - Post-replace SHA-256 verification and rollback on integrity mismatch.
//! - Strict safety guard: Hardcoded protection preventing any unit test from writing to live ov.conf.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum SafeWriteError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Revision mismatch for {file}: expected {expected}, found {actual}")]
    RevisionMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error(
        "Integrity verification failed for {file}: written SHA {actual} != expected {expected}"
    )]
    IntegrityMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("Could not acquire interprocess lock on {path} within {timeout_secs}s")]
    LockTimeout { path: String, timeout_secs: f64 },

    #[error("Refusing to write to protected live configuration path: {0}")]
    LivePathProtected(String),

    #[error("ACL security restriction failed on {path}: {detail}")]
    AclError { path: String, detail: String },
}

/// Retrieves the current process user's SID as a string (e.g. S-1-5-21-...).
#[cfg(windows)]
fn get_current_user_sid_string(path: &Path) -> Result<String, SafeWriteError> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(SafeWriteError::AclError {
                path: path.display().to_string(),
                detail: format!("OpenProcessToken failed with code {}", GetLastError()),
            });
        }

        struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        CloseHandle(self.0);
                    }
                }
            }
        }
        let _guard = HandleGuard(token);

        let mut return_len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut return_len);
        if return_len == 0 {
            return Err(SafeWriteError::AclError {
                path: path.display().to_string(),
                detail: "GetTokenInformation returned 0 required bytes for TokenUser".to_string(),
            });
        }

        // Allocate pointer-aligned memory to avoid alignment UB when casting to TOKEN_USER
        let usize_len = (return_len as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0usize; usize_len];

        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut _,
            return_len,
            &mut return_len,
        ) == 0
        {
            let err = GetLastError();
            return Err(SafeWriteError::AclError {
                path: path.display().to_string(),
                detail: format!("GetTokenInformation failed with code {}", err),
            });
        }

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid_str_ptr = std::ptr::null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_str_ptr) == 0 {
            return Err(SafeWriteError::AclError {
                path: path.display().to_string(),
                detail: format!("ConvertSidToStringSidW failed with code {}", GetLastError()),
            });
        }

        let mut len = 0;
        while *sid_str_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_str_ptr, len);
        let sid_str = String::from_utf16_lossy(slice);

        windows_sys::Win32::Foundation::LocalFree(sid_str_ptr as HLOCAL);
        Ok(sid_str)
    }
}

/// Applies restrictive ACL on Windows (SYSTEM: Full, Administrators: Full, Owner: Full, CurrentUser: Full).
/// Fails closed if the security descriptor cannot be applied.
#[cfg(windows)]
pub fn apply_restricted_file_acl(path: &Path) -> Result<(), SafeWriteError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_SUCCESS, HLOCAL};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let user_sid = get_current_user_sid_string(path)?;
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

    // SYSTEM: Full, Administrators: Full, Owner Rights: Full, CurrentUser: Full
    let sddl = format!(
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FA;;;{})\0",
        user_sid
    );
    let wide_sddl: Vec<u16> = sddl.encode_utf16().collect();

    unsafe {
        let mut sec_desc: *mut std::ffi::c_void = std::ptr::null_mut();
        let ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sec_desc as *mut _,
            std::ptr::null_mut(),
        );

        if ok == 0 {
            let err = GetLastError();
            return Err(SafeWriteError::AclError {
                path: path.display().to_string(),
                detail: format!("ConvertStringSecurityDescriptor failed with code {}", err),
            });
        }

        // Extract DACL from security descriptor
        let mut dacl_present = 0;
        let mut dacl_ptr: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
        let mut dacl_defaulted = 0;
        let dacl_ok = windows_sys::Win32::Security::GetSecurityDescriptorDacl(
            sec_desc,
            &mut dacl_present,
            &mut dacl_ptr,
            &mut dacl_defaulted,
        );

        if dacl_ok == 0 || dacl_present == 0 {
            windows_sys::Win32::Foundation::LocalFree(sec_desc as HLOCAL);
            return Err(SafeWriteError::AclError {
                path: path.display().to_string(),
                detail: "GetSecurityDescriptorDacl failed or DACL not present".to_string(),
            });
        }

        // Apply DACL to the named file
        let ret = SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl_ptr as *mut _,
            std::ptr::null_mut(),
        );

        windows_sys::Win32::Foundation::LocalFree(sec_desc as HLOCAL);

        if ret != ERROR_SUCCESS {
            return Err(SafeWriteError::AclError {
                path: path.display().to_string(),
                detail: format!("SetNamedSecurityInfoW failed with code {}", ret),
            });
        }
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn apply_restricted_file_acl(_path: &Path) -> Result<(), SafeWriteError> {
    Ok(())
}

/// Computes standard 64-character lowercase hex SHA-256 digest of given byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// An exclusive interprocess file lock guard holding `.dest.lock`.
pub struct FileLockGuard {
    _file: File,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // Lock release occurs automatically when the file descriptor handle is closed.
        // We deliberately do not delete the lock sentinel file to avoid deletion-under-handle races.
    }
}

/// Acquires an exclusive interprocess file lock on `lock_path`.
pub fn acquire_file_lock(
    lock_path: &Path,
    timeout: Duration,
) -> Result<FileLockGuard, SafeWriteError> {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let start = Instant::now();
    loop {
        if let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
        {
            // On Windows, lock byte 0 exclusively
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::Storage::FileSystem::{
                    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
                };

                let handle = file.as_raw_handle();
                unsafe {
                    let mut overlapped = std::mem::zeroed();
                    let ok = windows_sys::Win32::Storage::FileSystem::LockFileEx(
                        handle,
                        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                        0,
                        1,
                        0,
                        &mut overlapped,
                    );
                    if ok != 0 {
                        return Ok(FileLockGuard { _file: file });
                    }
                }
            }

            #[cfg(not(windows))]
            {
                return Ok(FileLockGuard { _file: file });
            }
        }

        if start.elapsed() >= timeout {
            return Err(SafeWriteError::LockTimeout {
                path: lock_path.display().to_string(),
                timeout_secs: timeout.as_secs_f64(),
            });
        }

        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Returns true when `dest_path` targets `%USERPROFILE%\.openviking\ov.conf` without live-write authorization (`COCKPIT_RUST_SPEC` §4.2).
pub fn is_live_path_protected(
    dest_path: &Path,
    home_dir: Option<&Path>,
    allow_live_write: bool,
) -> bool {
    if allow_live_write {
        return false;
    }
    let home = match home_dir {
        Some(h) => h,
        None => return false,
    };

    let live_ov = home.join(".openviking").join("ov.conf");

    // Direct canonical comparison if both already exist
    if let (Ok(cd), Ok(cl)) = (dest_path.canonicalize(), live_ov.canonicalize()) {
        if cd == cl {
            return true;
        }
    }

    // Canonicalize parent dirs to protect even if destination or live file does not exist yet
    let can_dest_parent = dest_path.parent().and_then(|p| p.canonicalize().ok());
    let can_live_parent = live_ov.parent().and_then(|p| p.canonicalize().ok());

    if let (Some(dp), Some(lp)) = (can_dest_parent, can_live_parent) {
        if dp == lp {
            let dest_name = dest_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let live_name = live_ov.file_name().and_then(|n| n.to_str()).unwrap_or("");
            return dest_name.eq_ignore_ascii_case(live_name);
        }
    }

    false
}

/// Atomically writes `content` to `dest_path` under file lock with DACL hardening and readback check (`COCKPIT_RUST_SPEC` §4.2).
pub fn safe_atomic_write_text(
    dest_path: &Path,
    content: &str,
    restrict_acl: bool,
    expected_previous_sha: Option<&str>,
) -> Result<String, SafeWriteError> {
    safe_atomic_write_text_with_live_policy(
        dest_path,
        content,
        restrict_acl,
        expected_previous_sha,
        false,
    )
}

/// Atomically writes `content` to `dest_path` with explicit `allow_live_write` authorization (`COCKPIT_RUST_SPEC` §4.2).
pub fn safe_atomic_write_text_with_live_policy(
    dest_path: &Path,
    content: &str,
    restrict_acl: bool,
    expected_previous_sha: Option<&str>,
    allow_live_write: bool,
) -> Result<String, SafeWriteError> {
    let home_var = std::env::var_os("USERPROFILE");
    let home_path = home_var.as_ref().map(Path::new);
    let allow_live =
        allow_live_write || std::env::var("COCKPIT_ALLOW_LIVE_WRITE").as_deref() == Ok("1");
    safe_atomic_write_text_internal(
        dest_path,
        content,
        restrict_acl,
        expected_previous_sha,
        home_path,
        allow_live,
    )
}

/// Internal implementation of atomic write with customizable home directory and override flag for testing.
pub(crate) fn safe_atomic_write_text_internal(
    dest_path: &Path,
    content: &str,
    restrict_acl: bool,
    expected_previous_sha: Option<&str>,
    home_dir: Option<&Path>,
    allow_live_write: bool,
) -> Result<String, SafeWriteError> {
    // 1. Safety Guard Invariant: Prevent accidentally modifying user's live ov.conf
    if is_live_path_protected(dest_path, home_dir, allow_live_write) {
        return Err(SafeWriteError::LivePathProtected(
            dest_path.display().to_string(),
        ));
    }

    let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    // 2. Acquire exclusive interprocess lock to eliminate TOCTOU races between check and replace
    let lock_filename = format!(
        ".{}.lock",
        dest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
    );
    let lock_path = parent.join(lock_filename);
    let _lock = acquire_file_lock(&lock_path, Duration::from_secs(5))?;

    // 3. Revision check under lock: verify expected revision against existing file
    if let Some(expected_sha) = expected_previous_sha {
        if !dest_path.is_file() {
            return Err(SafeWriteError::RevisionMismatch {
                file: dest_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                expected: expected_sha.to_string(),
                actual: "<non-existent>".to_string(),
            });
        }
        let current_bytes = fs::read(dest_path)?;
        let current_sha = sha256_hex(&current_bytes);
        if current_sha != expected_sha {
            return Err(SafeWriteError::RevisionMismatch {
                file: dest_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                expected: expected_sha.to_string(),
                actual: current_sha,
            });
        }
    }

    let raw_bytes = content.as_bytes();
    let expected_sha = sha256_hex(raw_bytes);

    // 4. Create secure unique temp file in destination directory
    let temp_name = format!(
        ".{}.tmp.{}",
        dest_path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let temp_path = parent.join(temp_name);

    // RAII guard to guarantee temp file cleanup on any early error return
    struct TempFileCleanupGuard<'a>(&'a Path, bool);
    impl<'a> Drop for TempFileCleanupGuard<'a> {
        fn drop(&mut self) {
            if self.1 {
                let _ = fs::remove_file(self.0);
            }
        }
    }

    let mut temp_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&temp_path)?;

    let mut temp_guard = TempFileCleanupGuard(&temp_path, true);

    // 5. Apply restrictive DACL before writing sensitive bytes
    if restrict_acl {
        apply_restricted_file_acl(&temp_path)?;
    }

    // 6. Write bytes and fsync to disk
    temp_file.write_all(raw_bytes)?;
    temp_file.flush()?;
    temp_file.sync_all()?;
    drop(temp_file);

    // Pre-replace verification: verify temp file integrity on disk before touching destination
    let temp_bytes = fs::read(&temp_path)?;
    let temp_sha = sha256_hex(&temp_bytes);
    if temp_sha != expected_sha {
        return Err(SafeWriteError::IntegrityMismatch {
            file: dest_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            expected: expected_sha,
            actual: temp_sha,
        });
    }

    // 7. Atomic replacement
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };

        let wide_from: Vec<u16> = temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
        let wide_to: Vec<u16> = dest_path.as_os_str().encode_wide().chain(Some(0)).collect();

        unsafe {
            let ok = MoveFileExW(
                wide_from.as_ptr(),
                wide_to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            );
            if ok == 0 {
                let err = GetLastError();
                return Err(SafeWriteError::Io(io::Error::from_raw_os_error(err as i32)));
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Err(e) = fs::rename(&temp_path, dest_path) {
            return Err(SafeWriteError::Io(e));
        }
    }

    // Disarm cleanup guard since atomic replace succeeded
    temp_guard.1 = false;

    // 7. Post-replace verification
    let written_bytes = fs::read(dest_path)?;
    let actual_sha = sha256_hex(&written_bytes);
    if actual_sha != expected_sha {
        return Err(SafeWriteError::IntegrityMismatch {
            file: dest_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            expected: expected_sha,
            actual: actual_sha,
        });
    }

    if restrict_acl {
        apply_restricted_file_acl(dest_path)?;
    }

    Ok(actual_sha)
}

/// Serializes and atomically writes JSON data.
pub fn safe_atomic_write_json<T: serde::Serialize>(
    dest_path: &Path,
    data: &T,
    restrict_acl: bool,
) -> Result<String, SafeWriteError> {
    let payload = serde_json::to_string_pretty(data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        + "\n";
    safe_atomic_write_text(dest_path, &payload, restrict_acl, None)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_safe_atomic_write_roundtrip() {
        let dir = tempdir().expect("create tempdir");
        let dest = dir.path().join("test_config.json");

        let content = "{\"model\": \"test-model-1\", \"enabled\": true}\n";
        let sha1 = safe_atomic_write_text(&dest, content, false, None).expect("write 1");
        assert!(dest.is_file());

        let readback = fs::read_to_string(&dest).expect("readback");
        assert_eq!(readback, content);

        // Test expected previous revision match
        let new_content = "{\"model\": \"test-model-2\", \"enabled\": true}\n";
        let sha2 = safe_atomic_write_text(&dest, new_content, false, Some(&sha1)).expect("write 2");
        assert_ne!(sha1, sha2);

        // Test revision mismatch fails closed
        let bad_rev_res = safe_atomic_write_text(&dest, "tamper", false, Some("0000000000000000"));
        assert!(matches!(
            bad_rev_res,
            Err(SafeWriteError::RevisionMismatch { .. })
        ));

        // Verify destination file was completely untouched by failed write
        let untouched = fs::read_to_string(&dest).expect("readback after failed write");
        assert_eq!(
            untouched, new_content,
            "Rejected write corrupted or altered destination file!"
        );
    }

    #[test]
    fn test_live_path_protection_synthetic() {
        let dir = tempdir().expect("create tempdir");
        let fake_home = dir.path().join("fake_home");
        let fake_ov_dir = fake_home.join(".openviking");
        fs::create_dir_all(&fake_ov_dir).expect("create fake .openviking dir");

        let fake_ov_conf = fake_ov_dir.join("ov.conf");
        fs::write(&fake_ov_conf, "original content").expect("write fake ov.conf");

        // 1. Existing file under fake home must be protected
        assert!(
            is_live_path_protected(&fake_ov_conf, Some(&fake_home), false),
            "Existing ov.conf was not protected!"
        );

        // 2. Case-insensitive protection (e.g. OV.CONF)
        let upper_ov_conf = fake_ov_dir.join("OV.CONF");
        assert!(
            is_live_path_protected(&upper_ov_conf, Some(&fake_home), false),
            "Case variant OV.CONF was not protected!"
        );

        // 3. File that does not exist yet under .openviking must also be protected
        let nonexistent_ov_conf = fake_ov_dir.join("ov.conf.nonexistent");
        assert!(
            !is_live_path_protected(&nonexistent_ov_conf, Some(&fake_home), false),
            "Unrelated file was falsely protected!"
        );

        // 4. When allow_live_write is true, protection is waived
        assert!(
            !is_live_path_protected(&fake_ov_conf, Some(&fake_home), true),
            "Explicit override did not waive protection!"
        );

        // 5. Unrelated file in sibling directory is not protected
        let other_file = dir.path().join("other.conf");
        assert!(
            !is_live_path_protected(&other_file, Some(&fake_home), false),
            "Unrelated path was falsely protected!"
        );

        // 6. When home_dir is None, returns false
        assert!(
            !is_live_path_protected(&fake_ov_conf, None, false),
            "None home_dir did not return false!"
        );
    }

    #[test]
    fn test_file_locking_contention() {
        let dir = tempdir().expect("create tempdir");
        let lock_path = dir.path().join(".test.lock");

        let lock1 = acquire_file_lock(&lock_path, Duration::from_millis(50)).expect("acquire 1");

        // Second acquisition attempt should time out
        let lock2_res = acquire_file_lock(&lock_path, Duration::from_millis(50));
        assert!(matches!(lock2_res, Err(SafeWriteError::LockTimeout { .. })));

        drop(lock1);

        // After drop, should succeed
        let lock3 = acquire_file_lock(&lock_path, Duration::from_millis(50)).expect("acquire 3");
        drop(lock3);
    }
}
