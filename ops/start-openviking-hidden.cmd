@echo off
rem OpenViking watchdog -- windowless variant.
rem Launched by start-openviking-hidden.vbs (wscript //B) from the "OpenViking Autostart" task,
rem so no console window ever appears on the desktop. Logs are the only surface.
rem
rem Differences from the legacy start-openviking.cmd:
rem   1. Waits use ping instead of timeout. timeout /t fails (rc=125) in a windowless
rem      console, which would turn the crash-restart delay into a hot spin loop.
rem   2. ollama serve writes its Gin access log to logs/ollama.log instead of the
rem      (now invisible) console buffer.
setlocal EnableExtensions
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONUNBUFFERED=1"
set "OLLAMA_HOST=127.0.0.1:21434"
set "HOME_DIR=C:/Users/rurus/.openviking"
set "SERVER=%HOME_DIR%/venv/Scripts/openviking-server.exe"
set "OLLAMA=C:/Users/rurus/AppData/Local/Programs/Ollama/ollama.exe"
set "LOG_DIR=%HOME_DIR%/logs"
set "LOG=%LOG_DIR%/server.log"
set "OLLAMA_LOG=%LOG_DIR%/ollama.log"
set "HEALTH=http://127.0.0.1:19330/health"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

rem One task owns one watchdog; if a healthy server exists, do nothing.
curl.exe -fsS --max-time 3 "%HEALTH%" >nul 2>&1
if not errorlevel 1 exit /b 0

:watchdog
rem Rotate logs near 4MB so the tail stays readable.
if exist "%LOG%" for %%A in ("%LOG%") do if %%~zA GTR 4194304 move /y "%LOG%" "%LOG%.old" >nul 2>&1
if exist "%OLLAMA_LOG%" for %%A in ("%OLLAMA_LOG%") do if %%~zA GTR 4194304 move /y "%OLLAMA_LOG%" "%OLLAMA_LOG%.old" >nul 2>&1
rem Ensure the Ollama API exists; the tray app can run without ollama serve.
curl.exe -fsS --max-time 3 http://127.0.0.1:21434/api/version >nul 2>&1
if errorlevel 1 (
  echo [%date% %time%] Ollama API unavailable; starting ollama serve.>>"%LOG_DIR%/ollama-boot.log"
  rem Mute Gin access log stdout to nul; keep stderr for genuine errors.
  start "Ollama Serve" /b "%OLLAMA%" serve >nul 2>>"%OLLAMA_LOG%"
  ping -n 16 127.0.0.1 >nul
  goto watchdog
)

rem Avoid a duplicate if another launcher brought the server up meanwhile.
curl.exe -fsS --max-time 3 "%HEALTH%" >nul 2>&1
if not errorlevel 1 exit /b 0

rem Clear a data-dir lock left by a recycled PID after reboot (crash-loop guard).
"%HOME_DIR%/venv/Scripts/python.exe" "%HOME_DIR%/ov_stale_lock_clean.py" >nul 2>&1

echo [%date% %time%] Starting OpenViking watchdog instance.>>"%LOG%"
"%SERVER%" >>"%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [%date% %time%] OpenViking exited with code %RC%; restarting in 10 seconds.>>"%LOG%"
ping -n 11 127.0.0.1 >nul
goto watchdog
