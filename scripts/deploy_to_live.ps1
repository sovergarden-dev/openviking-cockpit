param(
    [string]$LiveDir = "C:\Users\rurus\.openviking\monitor",
    [switch]$Apply,
    [string]$PythonExe = "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $PythonExe -PathType Leaf)) { throw "Python 3.11 interpreter not found: $PythonExe" }
$arguments = @((Join-Path $PSScriptRoot "monitor_sync.py"), "deploy", "--live", $LiveDir)
if ($Apply) { $arguments += "--apply" }
& $PythonExe @arguments
if ($LASTEXITCODE -ne 0) { throw "Monitor synchronization failed (exit $LASTEXITCODE). Read the receipt before retrying." }
