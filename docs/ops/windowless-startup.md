# Windowless OpenViking startup

OpenViking is launched by the Windows Scheduled Task **`OpenViking Autostart`**
(principal `MINH\Rurus`, `InteractiveToken`, no triggers — the Cockpit Monitor starts it
with `schtasks /Run` and restarts it with `/End` + `/Run`).

Historically the task ran `cmd.exe /d /c start-openviking.cmd`, which created a visible
console. That console showed the Ollama Gin access log (`GET /api/version`, 200, every ~11 s)
and duplicated what the Monitor already surfaces. The console is now removed from the desktop
entirely, and `logs/server.log` / `logs/ollama.log` are the only log surfaces.

## Chain

```
Scheduled Task "OpenViking Autostart"
  └─ wscript.exe //B  C:\Users\rurus\.openviking\start-openviking-hidden.vbs    (style 0)
       └─ cmd.exe /d /c  C:\Users\rurus\.openviking\start-openviking-hidden.cmd  (no window)
            ├─ ollama.exe serve      → logs/ollama.log
            └─ openviking-server.exe → logs/server.log
```

Files:

| Path | Role |
|---|---|
| `start-openviking-hidden.vbs` | Window-style-0 launcher invoked by the task |
| `start-openviking-hidden.cmd` | Authoritative watchdog (windowless-safe waits) |
| `start-openviking.cmd` | Legacy visible-console watchdog; not referenced by the task |
| `backups/task-xml/` | Pre-change task XML and legacy cmd snapshot |

## Why the watchdog body differs

`timeout /t N /nobreak` **returns 125 immediately inside a windowless console** (no console
input buffer), which would have converted the crash-restart delay and the Ollama warm-up wait
into a hot spin loop. Measured on this host:

```
timeout /t 3 /nobreak >nul   ->  rc=125  (does not wait)
ping -n 11 127.0.0.1 >nul    ->  waits 10.1 s
```

So the windowless variant waits with `ping -n (N+1) 127.0.0.1 >nul`.

`ollama serve` now runs as `start "Ollama Serve" /b "%OLLAMA%" serve >>"%OLLAMA_LOG%" 2>&1`
so its Gin access log lands in a file instead of an invisible console buffer (verified: both
stdout and stderr are captured through `start /b`).

## Restoring a visible console (diagnostics only)

Run the legacy watchdog by hand — never edit the file while a watchdog is running in it:

```cmd
C:\Users\rurus\.openviking\start-openviking.cmd
```

To revert the scheduled task:

```powershell
$action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe' `
  -Argument '/d /c "C:\Users\rurus\.openviking\start-openviking.cmd"'
Set-ScheduledTask -TaskName 'OpenViking Autostart' -Action $action
```

## Operational notes

- The legacy `start-openviking.cmd` is still held open by a running watchdog after the swap;
  it can be deleted once that chain has been recycled (reboot or Monitor restart).
- Hiding the *current* console window (rather than restarting the chain) was done with
  `ShowWindow(SW_HIDE)` on the Windows Terminal host window; the chain kept running and
  `/health` stayed 200 throughout.
- Windows 11 hands console ownership to `WindowsTerminal.exe`, so hiding `conhost.exe` alone
  does nothing — the visible window belongs to the terminal process.
