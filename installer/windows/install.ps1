#Requires -RunAsAdministrator
<#
.SYNOPSIS
    OS-DEFENDER 2.0 Windows Installer
.DESCRIPTION
    Installs the OS-DEFENDER agent and CLI, registers the Windows service,
    and creates the required directory structure.
#>

$ErrorActionPreference = "Stop"

$InstallDir = "$env:ProgramFiles\OS-DEFENDER"
$DataDir = "$env:ProgramData\OS-DEFENDER"
$ServiceName = "OSDefenderAgent"
$ServiceDisplayName = "OS-DEFENDER Protection Agent"

Write-Host "OS-DEFENDER 2.0 - Windows Installer" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path "$ScriptDir\..\..").Path

# Create directories
Write-Host "Creating directories..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path "$DataDir\quarantine" | Out-Null
New-Item -ItemType Directory -Force -Path "$DataDir\logs" | Out-Null

# Copy binaries
Write-Host "Installing binaries to $InstallDir"
Copy-Item "$RepoRoot\target\release\os-defender-agent.exe" "$InstallDir\" -Force
Copy-Item "$RepoRoot\target\release\os-defender.exe" "$InstallDir\" -Force

# Add to PATH
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$InstallDir*") {
    Write-Host "Adding $InstallDir to system PATH"
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
}

# Install config
if (-not (Test-Path "$DataDir\agent.toml")) {
    Write-Host "Creating default configuration"
    @"
[agent]
poll_interval_ms = 2000
heartbeat_timeout_secs = 60
policy_mode = "dry_run"
watch_dirs = "C:\Windows\System32\drivers\etc,C:\Users"

[storage]
db_path = "C:\ProgramData\OS-DEFENDER\os-defender.db"

[quarantine]
dir = "C:\ProgramData\OS-DEFENDER\quarantine"
"@ | Set-Content "$DataDir\agent.toml"
}

# Register Windows service
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "Registering Windows service: $ServiceName"
$binPath = "`"$InstallDir\os-defender-agent.exe`""
New-Service -Name $ServiceName `
    -BinaryPathName $binPath `
    -DisplayName $ServiceDisplayName `
    -Description "OS-DEFENDER real-time endpoint protection agent" `
    -StartupType Automatic | Out-Null

# Set service recovery options (restart on failure)
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "  Agent:   $InstallDir\os-defender-agent.exe"
Write-Host "  CLI:     $InstallDir\os-defender.exe"
Write-Host "  Data:    $DataDir"
Write-Host ""
Write-Host "Start with: Start-Service $ServiceName"
