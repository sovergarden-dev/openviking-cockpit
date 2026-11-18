//! Guarded OpenViking Windows service control (`OpenViking Autostart` task, socket-hang cleanup, and stale lock hygiene).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const AUTOSTART_TASK_NAME: &str = "OpenViking Autostart";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Restart,
}

impl ServiceAction {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "start" => Ok(Self::Start),
            "restart" => Ok(Self::Restart),
            other => Err(format!(
                "Unsupported service action '{}'; expected 'start' or 'restart'",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceStepReceipt {
    pub action: String,
    pub task_end_rc: Option<i32>,
    pub task_run_rc: i32,
    pub terminated_pids: Vec<u32>,
    pub locks_cleaned: Vec<String>,
}

/// Extracts deduplicated listening PIDs owning `port` from `netstat -ano -p tcp` output, excluding PID 0/4/`exclude_pid`.
pub fn parse_listening_pids_on_port(netstat_output: &str, port: u16, exclude_pid: u32) -> Vec<u32> {
    let suffix = format!(":{}", port);
    let mut pids = BTreeSet::new();
    for line in netstat_output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Standard Windows netstat -ano TCP line: TCP <local_addr> <foreign_addr> <state> <pid>
        if cols.len() < 5 || !cols[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        let local_addr = cols[1];
        let state = cols[3];
        if !state.eq_ignore_ascii_case("LISTENING") {
            continue;
        }
        if !local_addr.ends_with(&suffix) {
            continue;
        }
        let prefix_len = local_addr.len() - suffix.len();
        if prefix_len == 0 {
            continue;
        }
        // Verify exact port match (not e.g. :219330, though u16 max is 65535; guards IPv6 ::19330 ambiguity).
        let host_part = &local_addr[..prefix_len];
        if !host_part.ends_with("127.0.0.1")
            && !host_part.ends_with("0.0.0.0")
            && !host_part.ends_with("[::1]")
            && !host_part.ends_with("[::]")
        {
            continue;
        }
        if let Ok(pid) = cols[4].parse::<u32>() {
            if pid != 0 && pid != 4 && pid != exclude_pid {
                pids.insert(pid);
            }
        }
    }
    pids.into_iter().collect()
}

/// Parses bare numeric PIDs (one per line) emitted by PowerShell CIM queries, excluding 0, 4, and `exclude_pid`.
pub fn parse_numeric_pids(output: &str, exclude_pid: u32) -> Vec<u32> {
    let mut pids = BTreeSet::new();
    for line in output.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            if pid != 0 && pid != 4 && pid != exclude_pid {
                pids.insert(pid);
            }
        }
    }
    pids.into_iter().collect()
}

fn ensure_not_isolated_test_env() -> Result<(), String> {
    if std::env::var_os("COCKPIT_OV_HOME").is_some() {
        return Err(
            "Service control is disabled when COCKPIT_OV_HOME isolation is active".to_string(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn system32_exe(name: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|r| r.join("System32").join(name))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

#[cfg(windows)]
fn system_powershell_exe() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|r| {
            r.join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        })
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("powershell.exe"))
}

#[cfg(windows)]
fn run_hidden_cmd(exe: &Path, args: &[&str]) -> Result<(i32, String), String> {
    use std::os::windows::process::CommandExt;

    let out = std::process::Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute '{}': {}", exe.display(), e))?;
    let code = out.status.code().unwrap_or(1);
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.stderr.is_empty() {
        if !combined.is_empty() {
            combined.push(' ');
        }
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    Ok((code, combined))
}

/// Removes stale `data-*/.openviking.lock` files only when caller has verified no server process is running.
pub fn remove_leftover_data_locks(ov_home: &Path) -> Vec<String> {
    let mut removed = Vec::new();
    let Ok(entries) = fs::read_dir(ov_home) else {
        return removed;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        if !dir_name.starts_with("data") {
            continue;
        }
        let lock_path = path.join(".openviking.lock");
        if lock_path.is_file() && fs::remove_file(&lock_path).is_ok() {
            removed.push(format!("{}/.openviking.lock", dir_name));
        }
    }
    removed
}

#[cfg(windows)]
fn run_stale_pid_cleaner_if_present(ov_home: &Path) {
    use std::os::windows::process::CommandExt;
    let py = ov_home.join("venv").join("Scripts").join("python.exe");
    let script = ov_home.join("ov_stale_lock_clean.py");
    if py.is_file() && script.is_file() {
        let _ = std::process::Command::new(py)
            .arg(&script)
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

/// Executes the Windows Scheduled Task start or full socket-hang restart sequence synchronously.
/// Must be invoked inside `spawn_blocking` (`tauri.A1`).
#[cfg(windows)]
pub fn execute_service_step(
    action: ServiceAction,
    ov_home: &Path,
    port: u16,
) -> Result<ServiceStepReceipt, String> {
    ensure_not_isolated_test_env()?;

    let schtasks = system32_exe("schtasks.exe");
    let netstat = system32_exe("netstat.exe");
    let taskkill = system32_exe("taskkill.exe");
    let self_pid = std::process::id();

    let mut terminated_pids = Vec::new();
    let mut locks_cleaned = Vec::new();
    let mut task_end_rc = None;

    if action == ServiceAction::Restart {
        let (end_rc, _) = run_hidden_cmd(&schtasks, &["/End", "/TN", AUTOSTART_TASK_NAME])?;
        task_end_rc = Some(end_rc);
        std::thread::sleep(std::time::Duration::from_millis(1500));

        if let Ok((_, ns_out)) = run_hidden_cmd(&netstat, &["-ano", "-p", "tcp"]) {
            for pid in parse_listening_pids_on_port(&ns_out, port, self_pid) {
                let pid_str = pid.to_string();
                if let Ok((rc, _)) = run_hidden_cmd(&taskkill, &["/PID", &pid_str, "/T", "/F"]) {
                    if rc == 0 {
                        terminated_pids.push(pid);
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(800));

        // Check for hung socket-dead `openviking-server` processes still holding data-dir locks (`WinError 64`).
        let ps_query = "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'openviking[-]server' -or $_.CommandLine -match 'ov_lifecycle\\.py' } | ForEach-Object { $_.ProcessId }";
        if let Ok((0, ps_out)) = run_hidden_cmd(
            &system_powershell_exe(),
            &["-NoProfile", "-NonInteractive", "-Command", ps_query],
        ) {
            for pid in parse_numeric_pids(&ps_out, self_pid) {
                if terminated_pids.contains(&pid) {
                    continue;
                }
                let pid_str = pid.to_string();
                if let Ok((rc, _)) = run_hidden_cmd(&taskkill, &["/PID", &pid_str, "/T", "/F"]) {
                    if rc == 0 {
                        terminated_pids.push(pid);
                    }
                }
            }
        }

        // Verify port is now clear before unlinking `.openviking.lock`.
        let still_listening = run_hidden_cmd(&netstat, &["-ano", "-p", "tcp"])
            .map(|(_, ns)| !parse_listening_pids_on_port(&ns, port, self_pid).is_empty())
            .unwrap_or(true);
        if !still_listening {
            locks_cleaned = remove_leftover_data_locks(ov_home);
        }
    }

    run_stale_pid_cleaner_if_present(ov_home);

    let (run_rc, run_out) = run_hidden_cmd(&schtasks, &["/Run", "/TN", AUTOSTART_TASK_NAME])?;
    if run_rc != 0 {
        return Err(format!(
            "schtasks /Run '{}' failed (rc={}): {}",
            AUTOSTART_TASK_NAME,
            run_rc,
            run_out.trim()
        ));
    }

    Ok(ServiceStepReceipt {
        action: match action {
            ServiceAction::Start => "start".to_string(),
            ServiceAction::Restart => "restart".to_string(),
        },
        task_end_rc,
        task_run_rc: run_rc,
        terminated_pids,
        locks_cleaned,
    })
}

#[cfg(not(windows))]
pub fn execute_service_step(
    action: ServiceAction,
    _ov_home: &Path,
    _port: u16,
) -> Result<ServiceStepReceipt, String> {
    ensure_not_isolated_test_env()?;
    Err(format!(
        "Windows Scheduled Task control ({:?}) is only supported on Windows hosts",
        action
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_listening_pids_on_port_filters_exact_loopback_listeners() {
        let sample = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:19330        0.0.0.0:0              LISTENING       24100
  TCP    127.0.0.1:19330        127.0.0.1:54321        ESTABLISHED     24100
  TCP    0.0.0.0:19330          0.0.0.0:0              LISTENING       24108
  TCP    [::1]:19330            [::]:0                 LISTENING       24112
  TCP    127.0.0.1:21434        0.0.0.0:0              LISTENING       9999
  TCP    127.0.0.1:19330        0.0.0.0:0              LISTENING       0
  TCP    127.0.0.1:19330        0.0.0.0:0              LISTENING       7777
";
        let pids = parse_listening_pids_on_port(sample, 19330, 7777);
        assert_eq!(pids, vec![24100, 24108, 24112]);
    }

    #[test]
    fn test_parse_numeric_pids_deduplicates_and_excludes_reserved() {
        let out = "0\n4\n1234\n5678\n1234\n9999\ninvalid\n";
        assert_eq!(parse_numeric_pids(out, 9999), vec![1234, 5678]);
    }

    #[test]
    fn test_remove_leftover_data_locks_removes_only_lock_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("data-qwen06b");
        fs::create_dir_all(&data_dir).unwrap();
        let lock_file = data_dir.join(".openviking.lock");
        let keep_file = data_dir.join("important.db");
        fs::write(&lock_file, "locked").unwrap();
        fs::write(&keep_file, "keep").unwrap();

        let cleaned = remove_leftover_data_locks(tmp.path());
        assert_eq!(cleaned, vec!["data-qwen06b/.openviking.lock".to_string()]);
        assert!(!lock_file.exists());
        assert!(keep_file.exists());
    }

    #[test]
    fn test_service_action_parse_validates_verbs() {
        assert_eq!(ServiceAction::parse("start").unwrap(), ServiceAction::Start);
        assert_eq!(
            ServiceAction::parse("RESTART").unwrap(),
            ServiceAction::Restart
        );
        assert!(ServiceAction::parse("delete").is_err());
    }
}
