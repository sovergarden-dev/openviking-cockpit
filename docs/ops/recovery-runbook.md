# OpenViking Cockpit Disaster Recovery Runbook

> **Verified against commit:** `7652c17f8940fbabea1004f1f9680de158026bc2` (2026-11-12).
>
> **Tóm tắt vận hành:** Tài liệu này hướng dẫn kiểm tra, cô lập và phục hồi thủ công `monitor/monitor.json`, `ov.conf`, xử lý artifact `.REJECTED[-N].json`, siết quyền DACL backup cũ bằng `scripts/retrofit_ov_conf_backup_acl.py`, dọn lịch sử bằng `scripts/backup_retention.py`, và rollback mã nguồn Monitor qua `scripts/monitor_sync.py`. Mọi thao tác giữ nguyên tiến trình nền (`19330` OpenViking server, `21434` `ollama.exe`), không tự động khôi phục (`no auto-restore`), và giữ thư mục `backups/` ở chế độ **append-only**.

## Operational Invariants

- **No auto-restore:** Monitor never overwrites live state or configuration from a backup automatically. Recovery is always an explicit operator action.
- **Append-only backup archive:** Never edit historical receipts, manifests, or backup snapshots inside `%USERPROFILE%\.openviking\backups\` in place. If a follow-up check or redaction pass is required, emit a new dated artifact alongside a provenance addendum (`REDACTION.md`).
- **Confidentiality:** Never copy `monitor.json`, `ov.conf`, plaintext keys, `dpapi:` envelopes, or raw Windows principal SID/SDDL strings (`S-1-5-...`) into Git commits, issues, or chat logs.
- **Process isolation:** Keep the OpenViking server (`127.0.0.1:19330`) and `ollama.exe` (`127.0.0.1:21434`) running during state/config triage unless a configuration reload explicitly requires restarting the OpenViking service.
- **Repo-only maintenance scripts:** `scripts/retrofit_ov_conf_backup_acl.py`, `scripts/backup_retention.py`, and `scripts/monitor_sync.py` live in the repository and are not synced into `%USERPROFILE%\.openviking\monitor\`. Run them from the repository root with system Python 3.11 (`PYTHONPATH=` cleared).

---

## 1. Recovering `monitor/monitor.json` (`backups/monitor-state/<sha256>/`)

`save_state()` acquires `.monitor-state.lock`, computes `_state_revision` (the raw SHA-256 of exact UTF-8/disk bytes), and calls `backup_state(previous)` before any changed write when a prior revision exists (`revision is not None`). A genuine first-run write where `monitor.json` did not previously exist has no pre-image snapshot, which is why step 2 requires preserving any damaged file out-of-band first. Valid pre-change bytes are stored verbatim (preserving CRLF and `dpapi:` ciphertext) under:

```text
%USERPROFILE%\.openviking\backups\monitor-state\<sha256>\
  ├── monitor.json
  └── manifest.json   # { "sha256", "byte_count", "created_utc" }
```

### Verification and manual restore

1. **Close Monitor GUI only.** Confirm no `python*` process is running `openviking-monitor.pyw`. Do not stop OpenViking (`19330`) or `ollama.exe` (`21434`).
2. **Preserve the damaged file first.** Copy the damaged `%USERPROFILE%\.openviking\monitor\monitor.json` to a restricted-ACL forensic path outside live config before modifying anything.
3. **Verify candidate snapshot integrity and ACLs:**
   - Confirm `SHA-256(monitor.json)` matches both the folder name `<sha256>` and `manifest.json["sha256"]`, `byte_count` matches file length, and `created_utc` ends in `+00:00`.
   - Confirm via PowerShell `Get-Acl` that `AreAccessRulesProtected` is `$true` and the access DACL permits only `SYSTEM`, `Administrators`, and the current Windows user.
4. **Verify candidate JSON inside an isolated environment (no live network/state touch):**
   - Validate UTF-8 JSON structure and expected `watch_keys` / `spare_models` entries on a read-only copy inside a scratch directory (without writing to live `monitor/`).
   - Optionally run the backup state suite in isolation to confirm `backup_state()` machinery and ACL invariants on the current host (setting `$env:TMPDIR` explicitly keeps the command portable across pre-`824b3366` deployments too):
     ```powershell
     $env:PYTHONPATH = ""
     $env:TMPDIR = "$env:LOCALAPPDATA\hermes\cache\scratch"
     & "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe" monitor/tests/suite_bootstrap.py monitor/tests/test_state_backup.py
     ```
5. **Apply live only after verification:** Atomically replace `%USERPROFILE%\.openviking\monitor\monitor.json`, re-apply restricted permissions from the repository root with `safe_write.apply_restricted_file_acl` (do **not** use `icacls`, which can retain prior explicit grants such as `Everyone`; confirm `AreAccessRulesProtected -eq $true` via `Get-Acl`), re-verify its raw SHA-256 matches `manifest.json["sha256"]`, and then relaunch Monitor so a fresh session loads the restored revision. Never attempt to unlock a damaged or revision-locked runtime session in place:
   ```powershell
   # Run from the repository root
   $env:PYTHONPATH = ""
   & "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe" -c "import sys; from pathlib import Path; sys.path.insert(0, str(Path.cwd() / 'monitor')); from safe_write import apply_restricted_file_acl; assert apply_restricted_file_acl(Path.home() / '.openviking/monitor/monitor.json')"
   ```

### DPAPI & storage limits

- DPAPI ciphertext (`dpapi:...`) is bound to the current Windows user account and machine master key; same-user snapshots do not guarantee cross-machine or post-OS-reinstall decryption.
- `backups/monitor-state/` is an on-disk snapshot archive, not off-host backup.

---

## 2. Recovering `ov.conf` (`ov.conf-before-<reason>-<stamp>-<sha8>[-N].json`)

Every production edit flows through `apply_conf_edit()` -> `write_ov_conf_checked()` under `.ov-writer.lock`. Before writing, `backup_ov_conf(reason)` rejects reparse points on `OV_HOME`, `backups/`, `CONF_PATH`, and destinations, applies a protected `SYSTEM`/`Administrators`/current-user DACL to a temporary staging file before writing raw bytes, `fsync`s, reads back staging bytes, publishes without clobbering via Windows `os.rename` (`ov.conf-before-<reason>-<stamp>-<sha8>[-N].json`), and verifies final bytes and DACL.

- **Digest distinction:** `<sha8>` in the filename is the first 8 hex characters of the **raw-byte SHA-256** (`hashlib.sha256(raw_bytes).hexdigest()[:8]`). It is **not** canonical `_conf_digest(raw)` (sorted keys, compact JSON).
- **Manual restore steps:**
  1. **Close Monitor GUI first** and ensure no other `ov.conf` writer is active (a manual copy bypasses `.ov-writer.lock` and `expected_digest` checks; a live Monitor session with an older digest would fail closed on its next save).
  2. Verify the candidate `ov.conf-before-*.json` has `AreAccessRulesProtected -eq $true` and parses cleanly as UTF-8 JSON with no `dpapi:` ciphertext in `vlm.api_key` or `vlm.credentials[*].api_key`.
  3. Preserve the broken `ov.conf` separately, replace `%USERPROFILE%\.openviking\ov.conf` atomically, verify restricted ACL, and confirm `/health` and `/ready` on `127.0.0.1:19330` (a running OpenViking server may require an explicit operator restart before restored settings take effect; never restart automatically without authorization).

---

## 3. Triaging `.REJECTED[-N].json` & Checked-Write Asymmetry

`write_ov_conf_checked()` enforces an intentional **asymmetry** after `backup_ov_conf(reason)` returns:

| Condition inside `.ov-writer.lock` | Action on backup artifact | Write to `ov.conf` | `app.log` & UI signal |
|---|---|---|---|
| Backup unparseable, unreadable, or `backup_digest != expected_digest` | Renamed via `_quarantine_rejected_backup()` to `.REJECTED[-N].json` (first attempt uses no numeric suffix, then `-1` through `-63`; keeps original name on rename `OSError`) | **Blocked** (`RuntimeError`) | `app.log` logs `write_ov_conf_checked` (`unverifiable` / `drift`) with `quarantined=...` or `quarantine_failed=...`, plus `slot edit RuntimeError` |
| Backup matches `expected_digest`, but `CONF_PATH` drifted or became unreadable *after* backup | Valid `ov.conf-before-*.json` is **kept intact** as a clean pre-image (never marked `.REJECTED`) | **Blocked** (`RuntimeError`) | `app.log` logs only `slot edit RuntimeError`; `apply_conf_edit()` wraps the exception message (`"ov.conf current config not verifiable after backup; no write was made"` or `"ov.conf changed after backup; no write was made"`) under `"Không ghi được ov.conf.\n"` in the error dialog |

### Operator handling

- **Retention protection:** `scripts/backup_retention.py` matches `.REJECTED` in `PERMANENTLY_PROTECTED_PATTERNS`, so `.REJECTED[-N].json` files are never selected for quarantine even with `--keep-recent 0`.
- **When `quarantine_failed=` appears:** The unreadable/drifted artifact could not be renamed and still carries an `ov.conf-before-*` filename. Inspect `app.log`, verify whether the file is corrupt or stale, and do **not** restore from it blindly.
- **Retiring resolved forensic artifacts:** Only after verifying why the write aborted and confirming live `ov.conf` is healthy, move or delete the resolved `.REJECTED[-N].json` file manually.

---

## 4. Legacy ACL Retrofit (`scripts/retrofit_ov_conf_backup_acl.py`)

Hardens top-level `ov.conf-before-*.json` files in `%USERPROFILE%\.openviking\backups\` without altering bytes or `mtime_ns` (skips `.REJECTED`, `CONTAMINATED`, non-`.json`, subdirectories, and aborts fail-closed on reparse points):

```powershell
$env:PYTHONPATH = ""
# 1. Generate and inspect a redacted plan (PLAN_ONLY; no ACLs modified)
& "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe" scripts/retrofit_ov_conf_backup_acl.py --receipt C:\path\in\scratch\plan.json

# 2. Apply strictly against the reviewed plan (fails closed on any drift or missing sddl_sha256)
& "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe" scripts/retrofit_ov_conf_backup_acl.py --apply --plan-file C:\path\in\scratch\plan.json --receipt C:\path\in\scratch\receipt.json
```

- **Flags:** `--backup-dir` (default `%USERPROFILE%\.openviking\backups`), `--apply`, `--plan-file` (requires `--apply`; enforces exact parity on `name`, `path`, `size`, `mtime_ns`, `sha256`, `needs_harden`, `sddl_sha256`, and `skipped_protected`), `--receipt`.
- **Output modes & redaction:** Emits `PLAN_ONLY`, `APPLIED`, `APPLY_PARTIAL` (on mid-batch `Exception`/`KeyboardInterrupt`), or `APPLY_ABORTED` (on plan validation/drift failure), recording `plan_sha256` when `--plan-file` is used. Saved plans and receipts emit `sddl_sha256` / `sddl_after_sha256` digests only (no raw SDDL/SID strings; legacy plans lacking `sddl_sha256` fail closed and must be regenerated). Never commit plan or receipt JSON files to Git: keep them strictly in scratch paths outside the repository.

---

## 5. Backup Retention (`scripts/backup_retention.py`)

Dry-run by default; non-destructively moves expired snapshots into `backups/quarantine/batch-<stamp>/` with `quarantine-manifest.json` only when `--apply` is passed:

```powershell
$env:PYTHONPATH = ""
& "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe" scripts/backup_retention.py --keep-recent 10
```

- **Prunable categories:** Only top-level `ov.conf-before-*` and `monitor-sync-*` items beyond `--keep-recent` are eligible.
- **Never pruned automatically:** Items whose filename matches any substring in `PERMANENTLY_PROTECTED_PATTERNS` (`cleanup-mem-`, `OpenViking-Autostart-`, `CONTAMINATED`, `.REJECTED`, `live_safe_memories_`, `mem-phase`, `monitor-json-recovery`, `quarantine`) and uncategorized items such as `monitor-state/` (`other`) are always kept.

---

## 6. Source Synchronization & Rollback (`scripts/monitor_sync.py`)

`monitor_sync.py` synchronizes only Monitor application code (`CORE_FILES` + `monitor/tests/*.py`) between the repository and `%USERPROFILE%\.openviking\monitor\`. It never reads or writes `ov.conf` or `monitor.json`, and `docs/` / `scripts/` are **not** part of the sync manifest.

- **Default is plan-only:** Run `deploy` or `pull` without `--apply` to inspect SHA-256 differences first (`pull` refuses a dirty repository `monitor/` tree).
- **GUI guard:** `deploy --apply` runs `assert_monitor_stopped()` against both the target live directory and the repository source directory before staging and again before publishing; close all Monitor GUI instances first, then re-run `scripts/monitor_sync.py deploy --apply`.
- **Relaunch Monitor GUI after deploy:** Always launch using the canonical Python 3.11 path to prevent Windows PATH from resolving to a virtualenv lacking Tkinter:
  ```powershell
  Start-Process -FilePath "$env:LOCALAPPDATA\Programs\Python\Python311\pythonw.exe" -ArgumentList "`"$env:USERPROFILE\.openviking\monitor\openviking-monitor.pyw`"" -WorkingDirectory "$env:USERPROFILE\.openviking"
  ```
  Confirm the running process and interpreter path via:
  ```powershell
  Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'pythonw*' -and $_.CommandLine -like '*openviking-monitor.pyw*' } | Select-Object ProcessId, ExecutablePath, CommandLine
  ```
- **Rollback source files:** If a deployed Monitor update misbehaves, close Monitor GUI and restore files from `%USERPROFILE%\.openviking\backups\monitor-sync-<stamp>-<uuid8>\original\` using `receipt.json` as the file inventory.

---

## 7. Standalone Test Bootstrap (`suite_bootstrap.py`)

Running `suite_bootstrap.py` provisions an isolated home directory, filesystem audit guard blocking live `.openviking` access, and socket block on local/remote provider ports. When `TMPDIR` is unset or points to `%LOCALAPPDATA%\Temp`, the repository `suite_bootstrap.py` (`824b3366`+) assigns an isolated scratch `TMPDIR` and restores the caller's environment during cleanup. Legacy suites (`test_state_backup.py`, `test_state_revision.py`, `test_state_load_failure.py`, `test_watch_recovery.py`) intentionally read `os.environ['TMPDIR']` and fail fast if invoked directly without `suite_bootstrap.py`; until `scripts/monitor_sync.py deploy --apply` syncs an older `%USERPROFILE%\.openviking\monitor\tests\` tree, pass `$env:TMPDIR` explicitly when invoking tests from live.

---

## 8. Known Provenance Caveat

- The strict append-only rule in this runbook was formalized after the 2026-11-12 SDDL redaction pass, during which two pre-redaction verification receipts (`retrofit-plan-preapply.json` and `retrofit-receipt.json` inside an earlier deployment verification directory) were rewritten in place to replace `sddl_access`/`sddl_after` with `sddl_sha256`/`sddl_after_sha256`. Their pre-redaction bytes are unrecoverable; `REDACTION.md`, `manifest.json` (`derived: true`), and `post-redaction-reverification.json` document that `DERIVED` state and the independent live re-verification. All future derived attestations must be emitted as new files.
