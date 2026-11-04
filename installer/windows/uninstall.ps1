#Requires -RunAsAdministrator
<#
.SYNOPSIS
    OS-DEFENDER 2.0 Windows Uninstaller
.DESCRIPTION
    Stops and removes the OS-DEFENDER service and binaries.
    Data directory is preserved unless -RemoveData is specified.
#>
param(
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

$InstallDir = "$env:ProgramFiles\OS-DEFENDER"
$DataDir = "$env:ProgramData\OS-DEFENDER"
$ServiceName = "OSDefenderAgent"

Write-Host "OS-DEFENDER 2.0 - Windows Uninstaller" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Yellow

# Stop and remove service
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Write-Host "Removing service..."
    sc.exe delete $ServiceName | Out-Null
}

# Remove binaries
if (Test-Path $InstallDir) {
    Write-Host "Removing $InstallDir"
    Remove-Item -Recurse -Force $InstallDir
}

# Remove from PATH
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -like "*$InstallDir*") {
    $newPath = ($machinePath.Split(';') | Where-Object { $_ -ne $InstallDir }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    Write-Host "Removed from system PATH"
}

if ($RemoveData) {
    Write-Host "Removing data directory: $DataDir"
    Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
} else {
    Write-Host "Data directory preserved at: $DataDir"
    Write-Host "Remove manually or rerun with -RemoveData"
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
