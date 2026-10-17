# Pull source files from live OpenViking runtime directory into repo
param(
    [string]$LiveDir = "C:\Users\rurus\.openviking\monitor"
)

$ErrorActionPreference = "Stop"
$RepoMonitorDir = Join-Path $PSScriptRoot "..\monitor"

if (-not (Test-Path $LiveDir)) {
    Write-Error "Live directory not found: $LiveDir"
}

Write-Host "Pulling source files from $LiveDir to $RepoMonitorDir..." -ForegroundColor Cyan

# Core files to pull (strictly exclude monitor.json, app.log, security_reports, and backups)
$CoreFiles = @(
    "openviking-monitor.pyw",
    "provider_security_auditor.py",
    "reference_core_v31.py",
    "reserve_table.py",
    "openviking_monitor_notification.py",
    "openviking.ico"
)

foreach ($f in $CoreFiles) {
    $srcFile = Join-Path $LiveDir $f
    if (Test-Path $srcFile) {
        Copy-Item $srcFile -Destination $RepoMonitorDir -Force
        Write-Host " -> Pulled $f" -ForegroundColor Green
    }
}

# Pull tests
$LiveTestsDir = Join-Path $LiveDir "tests"
$RepoTestsDir = Join-Path $RepoMonitorDir "tests"
if (Test-Path $LiveTestsDir) {
    Get-ChildItem -Path $LiveTestsDir -Filter "*.py" | ForEach-Object {
        Copy-Item $_.FullName -Destination $RepoTestsDir -Force
        Write-Host " -> Pulled tests/$($_.Name)" -ForegroundColor Green
    }
}

Write-Host "Sync completed. No secrets, logs or database files were pulled into the repository." -ForegroundColor Yellow
