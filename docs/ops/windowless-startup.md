# Windowless OpenViking startup

OpenViking is launched by the Windows Scheduled Task **`OpenViking Autostart`** (`InteractiveToken`, with an `AtLogon` trigger for the interactive user, and on-demand start/restart from the Cockpit via `schtasks /Run` and `/End` + `/Run`).

Historically the task ran `cmd.exe /d /c start-openviking.cmd`, which created a visible console showing the Ollama Gin access log (`GET /api/version`, 200, every ~11 s) and duplicating what the Monitor already surfaces. The console is now removed from the desktop entirely, and `logs/server.log`, `logs/ollama.log`, and `logs/lifecycle.jsonl` are the only log surfaces.

## Chain

```
Scheduled Task "OpenViking Autostart"
  └─ wscript.exe //B  %USERPROFILE%\.openviking\start-openviking-hidden.vbs    (style 0)
       └─ cmd.exe /d /c  %USERPROFILE%\.openviking\start-openviking-hidden.cmd  (no window)
            ├─ ollama.exe serve      → logs/ollama.log (OLLAMA_KEEP_ALIVE=30m)
            └─ ov_lifecycle.py       → logs/lifecycle.jsonl (metadata) + logs/server.log (openviking-server -u -X faulthandler)
```

Files:

| Path | Role |
|---|---|
| `start-openviking-hidden.vbs` | Window-style-0 launcher invoked by the task |
| `start-openviking-hidden.cmd` | Authoritative watchdog (windowless-safe waits + `OLLAMA_KEEP_ALIVE=30m`) |
| `ov_stale_lock_clean.py` | Pre-launch PID/cmdline guard removing stale `data-qwen06b/.openviking.pid` locks |
| `ov_lifecycle.py` | Sanitized one-run child wrapper recording PID, hex exit code, and monotonic uptime to `logs/lifecycle.jsonl` |
| `start-openviking.cmd` | Legacy visible-console watchdog; not referenced by the task |
| `backups/task-xml/` | Pre-change task XML and legacy cmd snapshot |

## Why the watchdog body differs

`timeout /t N /nobreak` **returns 125 immediately inside a windowless console** (no console input buffer), which would have converted the crash-restart delay and the Ollama warm-up wait into a hot spin loop. Measured on Windows 11:

```
timeout /t 3 /nobreak >nul   ->  rc=125  (does not wait)
ping -n 11 127.0.0.1 >nul    ->  waits 10.1 s
```

So the windowless variant waits with `ping -n (N+1) 127.0.0.1 >nul`.

`ollama serve` runs as `start "Ollama Serve" /b "%OLLAMA%" serve >nul 2>>"%OLLAMA_LOG%"` with `OLLAMA_KEEP_ALIVE=30m` so the embedding model stays resident during active work while genuine errors land in `logs/ollama.log`.

## Restoring a visible console (diagnostics only)

Run the legacy watchdog by hand — never edit the file while a watchdog is running in it:

```cmd
"%USERPROFILE%\.openviking\start-openviking.cmd"
```

To revert the scheduled task:

```powershell
$action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe' `
  -Argument '/d /c "%USERPROFILE%\.openviking\start-openviking.cmd"'
Set-ScheduledTask -TaskName 'OpenViking Autostart' -Action $action
```

## Operational notes

- The legacy `start-openviking.cmd` is still held open by a running watchdog after a live swap; it can be deleted once that chain has been recycled (reboot or Monitor restart).
- Hiding an existing console window without restarting the chain uses `ShowWindow(SW_HIDE)` on the Windows Terminal host window; the chain keeps running and `/health` stays 200 throughout.
- Windows 11 hands console ownership to `WindowsTerminal.exe`, so hiding `conhost.exe` alone does nothing because the visible window belongs to the terminal process.
