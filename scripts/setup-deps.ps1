# OS-DEFENDER 2.0 — Automatic dependency installer for Windows.
# Run from an elevated (Administrator) PowerShell prompt.
# Usage: .\scripts\setup-deps.ps1 [-NoRust] [-NoPython] [-NoDesktop] [-NoVCTools]
param(
    [switch]$NoRust,
    [switch]$NoPython,
    [switch]$NoDesktop,
    [switch]$NoVCTools,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

if ($Help) {
    Write-Host "Usage: .\scripts\setup-deps.ps1 [-NoRust] [-NoPython] [-NoDesktop] [-NoVCTools]"
    exit 0
}

function Info($msg)  { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "[OK]   $msg" -ForegroundColor Green }
function Warn($msg)  { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Fail($msg)  { Write-Host "[FAIL] $msg" -ForegroundColor Red }

# --- Check admin ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Warn "Not running as Administrator. Some installations may fail."
    Warn "Re-run with: Start-Process powershell -Verb RunAs -ArgumentList '-File $($MyInvocation.MyCommand.Path)'"
}

# --- Helper: check if command exists ---
function Test-CommandExists($cmd) {
    try { Get-Command $cmd -ErrorAction Stop | Out-Null; return $true }
    catch { return $false }
}

# --- Helper: install via winget if available, fallback to direct download ---
$hasWinget = Test-CommandExists "winget"
if ($hasWinget) {
    Info "winget detected — will use it for installations"
} else {
    Warn "winget not found — will use direct downloads"
}

# --- 1. Visual C++ Build Tools ---
if (-not $NoVCTools) {
    $hasVS = (Test-Path "C:\Program Files\Microsoft Visual Studio") -or
             (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio") -or
             (Test-CommandExists "cl")

    if ($hasVS) {
        Info "Visual Studio / Build Tools detected"
    } else {
        Info "Installing Visual C++ Build Tools..."
        if ($hasWinget) {
            winget install --id Microsoft.VisualStudio.2022.BuildTools --accept-source-agreements --accept-package-agreements --silent --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
        } else {
            $vsUrl = "https://aka.ms/vs/17/release/vs_BuildTools.exe"
            $vsInstaller = "$env:TEMP\vs_BuildTools.exe"
            Info "Downloading Build Tools from $vsUrl ..."
            Invoke-WebRequest -Uri $vsUrl -OutFile $vsInstaller -UseBasicParsing
            Start-Process -Wait -FilePath $vsInstaller -ArgumentList "--passive", "--wait", "--add", "Microsoft.VisualStudio.Workload.VCTools", "--includeRecommended"
            Remove-Item $vsInstaller -Force -ErrorAction SilentlyContinue
        }
        Ok "Visual C++ Build Tools installed"
    }
} else {
    Info "Skipping Visual C++ Build Tools (--NoVCTools)"
}

# --- 2. Rust toolchain ---
if (-not $NoRust) {
    if (Test-CommandExists "rustup") {
        Info "Rust toolchain found — updating..."
        rustup update nightly
        rustup default nightly
    } else {
        Info "Installing Rust toolchain (nightly)..."
        if ($hasWinget) {
            winget install --id Rustlang.Rustup --accept-source-agreements --accept-package-agreements --silent
        } else {
            $rustupUrl = "https://win.rustup.rs/x86_64"
            $rustupExe = "$env:TEMP\rustup-init.exe"
            Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupExe -UseBasicParsing
            Start-Process -Wait -FilePath $rustupExe -ArgumentList "-y", "--default-toolchain", "nightly"
            Remove-Item $rustupExe -Force -ErrorAction SilentlyContinue
        }
        # Refresh PATH
        $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    }
    rustup component add clippy rustfmt 2>$null
    $rustVer = (rustc --version) -replace "rustc ",""
    Ok "Rust $rustVer installed"
} else {
    Info "Skipping Rust installation (-NoRust)"
}

# --- 3. Node.js (for desktop) ---
if (-not $NoDesktop) {
    if (Test-CommandExists "node") {
        $nodeVer = node --version
        Info "Node.js $nodeVer found"
    } else {
        Info "Installing Node.js 20 LTS..."
        if ($hasWinget) {
            winget install --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements --silent
        } else {
            Warn "Install Node.js 20+ manually from https://nodejs.org"
        }
    }

    $packageJson = Join-Path $RepoRoot "desktop\package.json"
    if (Test-Path $packageJson) {
        Info "Installing desktop frontend dependencies..."
        Push-Location (Join-Path $RepoRoot "desktop")
        try {
            npm ci 2>$null
            if ($LASTEXITCODE -ne 0) { npm install }
        } finally {
            Pop-Location
        }
        Ok "Desktop frontend dependencies installed"
    }
} else {
    Info "Skipping desktop/Node.js setup (-NoDesktop)"
}

# --- 4. Python + AI dependencies ---
if (-not $NoPython) {
    if (Test-CommandExists "python") {
        $pyVer = (python --version 2>&1) -replace "Python ",""
        Info "Python $pyVer found"
    } else {
        Info "Installing Python 3..."
        if ($hasWinget) {
            winget install --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements --silent
        } else {
            Warn "Install Python 3.11+ manually from https://python.org"
        }
        # Refresh PATH
        $env:PATH = "$env:LOCALAPPDATA\Programs\Python\Python312;$env:LOCALAPPDATA\Programs\Python\Python312\Scripts;$env:PATH"
    }

    $pyproject = Join-Path $RepoRoot "ai\pyproject.toml"
    if (Test-Path $pyproject) {
        Info "Setting up Python AI environment..."
        Push-Location (Join-Path $RepoRoot "ai")
        try {
            if (-not (Test-Path ".venv")) {
                python -m venv .venv
            }
            & .\.venv\Scripts\Activate.ps1
            python -m pip install -q --upgrade pip
            python -m pip install -q -e ".[dev]"
            deactivate
        } finally {
            Pop-Location
        }
        Ok "Python AI environment ready"
    }
} else {
    Info "Skipping Python setup (-NoPython)"
}

# --- Summary ---
Write-Host ""
Write-Host "==========================================" -ForegroundColor White
Info "OS-DEFENDER 2.0 dependency setup complete"
Write-Host "==========================================" -ForegroundColor White
Write-Host ""
Write-Host "  Build the project:"
Write-Host "    cargo build --release"
Write-Host ""
Write-Host "  Run tests:"
Write-Host "    cargo test; cargo clippy -- -D warnings"
Write-Host ""
if (-not $NoPython) {
    Write-Host "  Run AI tests:"
    Write-Host "    cd ai; .\.venv\Scripts\Activate.ps1; pytest; ruff check ."
    Write-Host ""
}
if (-not $NoDesktop) {
    Write-Host "  Build desktop app:"
    Write-Host "    cd desktop; npx tauri build"
    Write-Host ""
}
Write-Host "  Install (Windows):"
Write-Host "    .\installer\windows\install.ps1"
Write-Host ""
