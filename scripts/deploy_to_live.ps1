# Deploy from repo to live OpenViking runtime directory
param(
    [string]$LiveDir = "C:\Users\rurus\.openviking\monitor"
)

$ErrorActionPreference = "Stop"
$RepoMonitorDir = Join-Path $PSScriptRoot "..\monitor"

if (-not (Test-Path $LiveDir)) {
    Write-Error "Live directory not found: $LiveDir"
}

Write-Host "Deploying source files from $RepoMonitorDir to $LiveDir..." -ForegroundColor Cyan

# Copy python source files
Get-ChildItem -Path $RepoMonitorDir -Filter "*.py*" | ForEach-Object {
    Copy-Item $_.FullName -Destination $LiveDir -Force
    Write-Host " -> Copied $($_.Name)" -ForegroundColor Green
}

# Copy icon
if (Test-Path (Join-Path $RepoMonitorDir "openviking.ico")) {
    Copy-Item (Join-Path $RepoMonitorDir "openviking.ico") -Destination $LiveDir -Force
    Write-Host " -> Copied openviking.ico" -ForegroundColor Green
}

# Copy test suites
$LiveTestsDir = Join-Path $LiveDir "tests"
if (-not (Test-Path $LiveTestsDir)) {
    New-Item -ItemType Directory -Path $LiveTestsDir -Force | Out-Null
}

$RepoTestsDir = Join-Path $RepoMonitorDir "tests"
Get-ChildItem -Path $RepoTestsDir -Filter "*.py" | ForEach-Object {
    Copy-Item $_.FullName -Destination $LiveTestsDir -Force
    Write-Host " -> Copied tests/$($_.Name)" -ForegroundColor Green
}

Write-Host "Deployment completed successfully. Secrets and logs in live directory remained untouched." -ForegroundColor Yellow
