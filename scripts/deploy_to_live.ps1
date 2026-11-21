param(
    [ValidateSet("CockpitRs", "LegacyPython")]
    [string]$Target = "CockpitRs",
    [string]$OvHome = "$env:USERPROFILE\.openviking",
    [string]$LiveDir = "",
    [switch]$SyncOps,
    [switch]$SyncAntigravityPlugin,
    [switch]$SyncShortcuts,
    [switch]$Apply,
    [string]$PythonExe = "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
)
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$LiveMonitorDir = if ($LiveDir) { $LiveDir } else { Join-Path $OvHome "monitor" }

if ($Target -eq "LegacyPython") {
    if (-not (Test-Path $PythonExe -PathType Leaf)) {
        throw "Python 3.11 interpreter not found: $PythonExe"
    }
    $arguments = @((Join-Path $PSScriptRoot "monitor_sync.py"), "deploy", "--live", $LiveMonitorDir)
    if ($Apply) { $arguments += "--apply" }
    & $PythonExe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Legacy Python Monitor synchronization failed (exit $LASTEXITCODE)."
    }
    exit 0
}

$TauriManifest = Join-Path $RepoRoot "cockpit_rs\src-tauri\Cargo.toml"
$BuiltExe = Join-Path $RepoRoot "cockpit_rs\src-tauri\target\release\openviking-cockpit.exe"
$LiveExe = Join-Path $LiveMonitorDir "openviking-cockpit.exe"
$OpsPairs = @(
    @{ Src = (Join-Path $RepoRoot "ops\ov_lifecycle.py"); Dst = (Join-Path $OvHome "ov_lifecycle.py") },
    @{ Src = (Join-Path $RepoRoot "ops\ov_stale_lock_clean.py"); Dst = (Join-Path $OvHome "ov_stale_lock_clean.py") },
    @{ Src = (Join-Path $RepoRoot "ops\start-openviking-hidden.cmd"); Dst = (Join-Path $OvHome "start-openviking-hidden.cmd") },
    @{ Src = (Join-Path $RepoRoot "ops\start-openviking-hidden.vbs"); Dst = (Join-Path $OvHome "start-openviking-hidden.vbs") }
)

if (-not $Apply) {
    Write-Output "[PLAN ONLY] Target=CockpitRs | LiveExe=$LiveExe | SyncOps=$SyncOps | SyncShortcuts=$SyncShortcuts"
    foreach ($p in $OpsPairs) {
        Write-Output ("  OpsCandidate: " + $p.Src + " -> " + $p.Dst)
    }
    Write-Output "Pass -Apply (and optionally -SyncOps, -SyncAntigravityPlugin, -SyncShortcuts) to build --release and deploy atomically."
    exit 0
}

& cargo build --manifest-path $TauriManifest --release
if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed (exit $LASTEXITCODE)." }

if (-not (Test-Path $LiveMonitorDir -PathType Container)) {
    New-Item -ItemType Directory -Path $LiveMonitorDir -Force | Out-Null
}

Get-Process -Name "openviking-cockpit" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

$TmpExe = "$LiveExe.tmp"
Copy-Item -Path $BuiltExe -Destination $TmpExe -Force
Move-Item -Path $TmpExe -Destination $LiveExe -Force

$BuiltSha = (Get-FileHash -Path $BuiltExe -Algorithm SHA256).Hash.ToLower()
$LiveSha = (Get-FileHash -Path $LiveExe -Algorithm SHA256).Hash.ToLower()
if ($BuiltSha -ne $LiveSha) {
    throw "Binary SHA-256 verification failed: $BuiltSha != $LiveSha"
}
Write-Output "DEPLOYED_COCKPIT_EXE=$LiveExe SHA256=$LiveSha"

if ($SyncOps) {
    foreach ($p in $OpsPairs) {
        $tmp = $p.Dst + ".tmp"
        Copy-Item -Path $p.Src -Destination $tmp -Force
        Move-Item -Path $tmp -Destination $p.Dst -Force
        $s1 = (Get-FileHash -Path $p.Src -Algorithm SHA256).Hash.ToLower()
        $s2 = (Get-FileHash -Path $p.Dst -Algorithm SHA256).Hash.ToLower()
        if ($s1 -ne $s2) { throw "Ops SHA-256 mismatch on $($p.Dst)" }
        Write-Output ("SYNCED_OPS=" + $p.Dst + " SHA256=" + $s2)
    }
}

if ($SyncAntigravityPlugin) {
    if (-not (Test-Path $PythonExe -PathType Leaf)) {
        throw "Python 3.11 interpreter not found for Antigravity plugin sync: $PythonExe"
    }
    $PluginInstaller = Join-Path $PSScriptRoot "install_antigravity_plugin.py"
    & $PythonExe -X utf8 $PluginInstaller --python-exe $PythonExe --apply
    if ($LASTEXITCODE -ne 0) {
        throw "Antigravity plugin installation failed (exit $LASTEXITCODE)."
    }
}

if ($SyncShortcuts) {
    $IconPath = Join-Path $LiveMonitorDir "openviking.ico"
    $Ws = New-Object -ComObject WScript.Shell
    $ShortcutSpecs = @(
        @{ Path = (Join-Path $env:USERPROFILE "Desktop\OpenViking Monitor.lnk"); Args = ""; Optional = $false },
        @{ Path = (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\OpenViking Monitor.lnk"); Args = ""; Optional = $false },
        @{ Path = (Join-Path $LiveMonitorDir "OpenViking Monitor.lnk"); Args = ""; Optional = $false },
        @{ Path = (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\OpenViking Monitor.lnk"); Args = "--tray"; Optional = $true }
    )
    foreach ($spec in $ShortcutSpecs) {
        if ($spec.Optional -and -not (Test-Path -LiteralPath $spec.Path)) {
            continue
        }
        $parentDir = Split-Path -Parent $spec.Path
        if (-not (Test-Path -LiteralPath $parentDir -PathType Container)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
        $sc = $Ws.CreateShortcut($spec.Path)
        $sc.TargetPath = $LiveExe
        $sc.Arguments = $spec.Args
        $sc.WorkingDirectory = $LiveMonitorDir
        if (Test-Path -LiteralPath $IconPath -PathType Leaf) {
            $sc.IconLocation = "$IconPath,0"
        }
        $sc.Description = "OpenViking Cockpit"
        $sc.Save()
        Write-Output ("SYNCED_SHORTCUT=" + $spec.Path + " -> " + $LiveExe + $(if ($spec.Args) { " " + $spec.Args } else { "" }))
    }
}
