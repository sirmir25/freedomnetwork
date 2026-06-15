# FreedomNet installer for Windows (PowerShell 5.1+)
# Run as regular user; will prompt for admin only when required.
#
# Usage (from PowerShell):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\scripts\install-windows.ps1
#
# Or one-line install:
#   irm https://raw.githubusercontent.com/sirmir25/freedomnetwork/main/scripts/install-windows.ps1 | iex

#Requires -Version 5.1
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\FreedomNet",
    [switch]$NoAutoStart,
    [switch]$NoVpnGen,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ── colours ───────────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "[fninstall] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "⚠ $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "✗ $msg" -ForegroundColor Red; exit 1 }

# ── helpers ───────────────────────────────────────────────────────────────────
function Test-Command($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function Invoke-Download($url, $dest) {
    Write-Step "Downloading $url"
    [System.Net.WebClient]::new().DownloadFile($url, $dest)
}

function Add-ToPath($dir) {
    $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    if ($userPath -notlike "*$dir*") {
        [Environment]::SetEnvironmentVariable('PATH', "$userPath;$dir", 'User')
        $env:PATH += ";$dir"
        Write-Ok "Added $dir to user PATH"
    }
}

# ── banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "FreedomNet Windows Installer" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "─────────────────────────────────────────────────────────" -ForegroundColor Blue
Write-Host "  OS:   $([System.Environment]::OSVersion.VersionString)"
Write-Host "  Arch: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
Write-Host ""

# ── winget / scoop / choco detection ─────────────────────────────────────────
$pkgMgr = $null
if (Test-Command 'winget') { $pkgMgr = 'winget' }
elseif (Test-Command 'scoop') { $pkgMgr = 'scoop' }
elseif (Test-Command 'choco') { $pkgMgr = 'choco' }
Write-Step "Package manager: $($pkgMgr ?? 'none detected')"

# ── Git ───────────────────────────────────────────────────────────────────────
function Install-Git {
    if (Test-Command 'git') { Write-Ok "Git already installed"; return }
    Write-Step "Installing Git..."
    switch ($pkgMgr) {
        'winget' { winget install --id Git.Git -e --source winget --silent }
        'scoop'  { scoop install git }
        'choco'  { choco install git -y }
        default  {
            $tmpGit = "$env:TEMP\git-installer.exe"
            Invoke-Download 'https://github.com/git-for-windows/git/releases/download/v2.45.0.windows.1/Git-2.45.0-64-bit.exe' $tmpGit
            Start-Process $tmpGit -ArgumentList '/VERYSILENT /NORESTART' -Wait
            Remove-Item $tmpGit
        }
    }
    Write-Ok "Git installed"
}

# ── Rust ──────────────────────────────────────────────────────────────────────
function Install-Rust {
    if (Test-Command 'rustc') { Write-Ok "Rust $(rustc --version) already installed"; return }
    Write-Step "Installing Rust via rustup..."
    $tmpRust = "$env:TEMP\rustup-init.exe"
    Invoke-Download 'https://win.rustup.rs/x86_64' $tmpRust
    Start-Process $tmpRust -ArgumentList '-y --profile minimal' -Wait
    Remove-Item $tmpRust
    $env:PATH += ";$env:USERPROFILE\.cargo\bin"
    Add-ToPath "$env:USERPROFILE\.cargo\bin"
    Write-Ok "Rust installed"
}

# ── Visual Studio Build Tools (for C++ compilation) ──────────────────────────
function Install-BuildTools {
    # Check if MSVC link.exe is available
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -property installationPath 2>$null
        if ($vsPath) { Write-Ok "Visual Studio Build Tools found at $vsPath"; return }
    }

    # Check for pre-installed cl.exe
    if (Test-Command 'cl') { Write-Ok "MSVC cl.exe already in PATH"; return }

    Write-Step "Installing Visual Studio Build Tools (C++ workload)..."
    Write-Warn "This downloads ~4 GB and may take several minutes..."

    switch ($pkgMgr) {
        'winget' {
            winget install --id Microsoft.VisualStudio.2022.BuildTools `
                -e --source winget --silent `
                --override '--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
        }
        'choco' {
            choco install visualstudio2022buildtools -y `
                --params '--add Microsoft.VisualStudio.Workload.VCTools'
        }
        default {
            $tmpVS = "$env:TEMP\vs_buildtools.exe"
            Invoke-Download 'https://aka.ms/vs/17/release/vs_buildtools.exe' $tmpVS
            Start-Process $tmpVS `
                -ArgumentList '--quiet --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended' `
                -Wait
            Remove-Item $tmpVS
        }
    }
    Write-Ok "Visual Studio Build Tools installed"
}

# ── D compiler (DMD or LDC) ───────────────────────────────────────────────────
function Install-DCompiler {
    if ($NoVpnGen) { Write-Warn "Skipping D compiler (--NoVpnGen)"; return }
    if (Test-Command 'ldc2') { Write-Ok "ldc2 already installed"; return }
    if (Test-Command 'dmd')  { Write-Ok "dmd already installed"; return }

    Write-Step "Installing LDC2 D compiler..."
    switch ($pkgMgr) {
        'scoop' { scoop install ldc }
        'choco' { choco install ldc2 -y }
        default {
            # Download from GitHub releases
            $ldcVer = '1.37.0'
            $ldcUrl = "https://github.com/ldc-developers/ldc/releases/download/v$ldcVer/ldc2-$ldcVer-windows-multilib.7z"
            $ldcDir = "$env:LOCALAPPDATA\ldc2"
            $tmp7z  = "$env:TEMP\ldc2.7z"
            Invoke-Download $ldcUrl $tmp7z

            # Requires 7-Zip
            if (Test-Command '7z') {
                7z x $tmp7z -o"$env:LOCALAPPDATA" -y
                Add-ToPath "$ldcDir\bin"
            } else {
                Write-Warn "7-Zip not found. Install ldc2 manually from https://dlang.org"
            }
            Remove-Item $tmp7z -ErrorAction SilentlyContinue
        }
    }
    if (Test-Command 'ldc2') { Write-Ok "ldc2 installed" }
    else { Write-Warn "ldc2 not available. VPN generator won't be built." }
}

# ── clone / update repo ───────────────────────────────────────────────────────
function Sync-Repo {
    if (Test-Path "$InstallDir\.git") {
        Write-Step "Updating existing clone at $InstallDir..."
        Push-Location $InstallDir
        git pull --ff-only
        Pop-Location
    } else {
        Write-Step "Cloning to $InstallDir..."
        git clone 'https://github.com/sirmir25/freedomnetwork.git' $InstallDir
    }
    Write-Ok "Source at $InstallDir"
}

# ── build ─────────────────────────────────────────────────────────────────────
function Build-Proxy {
    Write-Step "Building FreedomNet proxy (Rust + C++)..."
    Push-Location $InstallDir
    cargo build --release
    Pop-Location
    Write-Ok "Proxy built: $InstallDir\target\release\fn.exe"
}

function Build-VpnGen {
    if ($NoVpnGen) { return }
    $dc = $null
    if (Test-Command 'ldc2') { $dc = 'ldc2' }
    elseif (Test-Command 'dmd') { $dc = 'dmd' }
    if (-not $dc) { Write-Warn "No D compiler; skipping VPN generator"; return }

    Write-Step "Building VPN generator (D)..."
    $sources = Get-ChildItem "$InstallDir\vpngen\source\*.d" | ForEach-Object { $_.FullName }
    & $dc -O2 -of="$InstallDir\vpngen\fn-vpn.exe" $sources
    Write-Ok "VPN generator built"
}

# ── install to PATH location ──────────────────────────────────────────────────
function Install-Bins {
    $binDir = "$InstallDir\bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null

    Copy-Item "$InstallDir\target\release\fn.exe" "$binDir\fn.exe" -Force
    Write-Ok "Installed: $binDir\fn.exe"

    if (Test-Path "$InstallDir\vpngen\fn-vpn.exe") {
        Copy-Item "$InstallDir\vpngen\fn-vpn.exe" "$binDir\fn-vpn.exe" -Force
        Write-Ok "Installed: $binDir\fn-vpn.exe"
    }

    Add-ToPath $binDir
}

# ── optional auto-start via Task Scheduler ────────────────────────────────────
function Install-AutoStart {
    if ($NoAutoStart) { return }

    $reply = Read-Host "`nInstall Windows Task Scheduler auto-start? [y/N]"
    if ($reply -notmatch '^[yY]$') { return }

    $action  = New-ScheduledTaskAction  -Execute "$InstallDir\bin\fn.exe"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 3

    Register-ScheduledTask `
        -TaskName 'FreedomNet DPI Bypass' `
        -Action   $action `
        -Trigger  $trigger `
        -Settings $settings `
        -RunLevel Limited `
        -Force | Out-Null

    Write-Ok "Auto-start task registered in Task Scheduler"
    Write-Ok "Manage with: taskschd.msc"
}

# ── configure browser ─────────────────────────────────────────────────────────
function Show-BrowserConfig {
    Write-Host ""
    Write-Host "Browser configuration" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Firefox:  Settings -> General -> Network Settings -> Manual proxy"
    Write-Host "            SOCKS v5: 127.0.0.1  Port: 1080"
    Write-Host "            Check: Proxy DNS when using SOCKS v5"
    Write-Host ""
    Write-Host "  Chrome/Edge:"
    Write-Host "    chrome.exe --proxy-server='socks5://127.0.0.1:1080'"
    Write-Host ""
    Write-Host "  PAC auto-config:"
    Write-Host "    Settings -> Internet Options -> Connections -> LAN Settings"
    Write-Host "    Use automatic configuration script:"
    Write-Host "    http://127.0.0.1:8085/proxy.pac"
    Write-Host ""
    Write-Host "  PowerShell:"
    Write-Host "    `$env:ALL_PROXY = 'socks5://127.0.0.1:1080'"
    Write-Host ""
}

# ── main ──────────────────────────────────────────────────────────────────────
Install-Git
Install-Rust
Install-BuildTools
Install-DCompiler
Sync-Repo
Build-Proxy
Build-VpnGen
Install-Bins
Install-AutoStart
Show-BrowserConfig

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Start the proxy:"
Write-Host "  fn"
Write-Host ""
Write-Host "Check blocked sites:"
Write-Host "  fn-vpn check google.com youtube.com bbc.com"
Write-Host ""
