#!/usr/bin/env bash
# OS-DEFENDER 2.0 — Automatic dependency installer for Linux.
# Detects the distribution and installs all build + runtime dependencies.
# Usage: ./scripts/setup-deps.sh [--no-rust] [--no-python] [--no-desktop]
set -euo pipefail

NO_RUST=false
NO_PYTHON=false
NO_DESKTOP=false
for arg in "$@"; do
    case "$arg" in
        --no-rust)   NO_RUST=true ;;
        --no-python) NO_PYTHON=true ;;
        --no-desktop) NO_DESKTOP=true ;;
        --help|-h)
            echo "Usage: $0 [--no-rust] [--no-python] [--no-desktop]"
            exit 0
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m   $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
fail()  { echo -e "\033[1;31m[FAIL]\033[0m $*"; }

# --- Detect distro ---
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
info "Detected distribution: $DISTRO"

# --- Package manager commands ---
case "$DISTRO" in
    ubuntu|debian|linuxmint|pop)
        PM="apt-get"
        INSTALL="sudo apt-get install -y"
        UPDATE="sudo apt-get update"
        ;;
    fedora)
        PM="dnf"
        INSTALL="sudo dnf install -y"
        UPDATE="sudo dnf check-update || true"
        ;;
    centos|rhel|rocky|alma)
        PM="yum"
        INSTALL="sudo yum install -y"
        UPDATE="sudo yum check-update || true"
        ;;
    arch|manjaro|endeavouros)
        PM="pacman"
        INSTALL="sudo pacman -S --noconfirm --needed"
        UPDATE="sudo pacman -Sy"
        ;;
    opensuse*|suse|sles)
        PM="zypper"
        INSTALL="sudo zypper install -y"
        UPDATE="sudo zypper refresh"
        ;;
    *)
        warn "Unsupported distro: $DISTRO — installing generic deps"
        PM="unknown"
        ;;
esac

# --- 1. System packages ---
info "Installing system build dependencies..."
if [ "$PM" != "unknown" ]; then
    $UPDATE 2>/dev/null || true
fi

case "$DISTRO" in
    ubuntu|debian|linuxmint|pop)
        $INSTALL build-essential pkg-config libssl-dev curl git
        if [ "$NO_DESKTOP" = false ]; then
            $INSTALL libwebkit2gtk-4.1-dev libappindicator3-dev \
                     librsvg2-dev patchelf libgtk-3-dev
        fi
        ;;
    fedora)
        $INSTALL gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl git
        if [ "$NO_DESKTOP" = false ]; then
            $INSTALL webkit2gtk4.1-devel libappindicator-gtk3-devel \
                     librsvg2-devel gtk3-devel patchelf
        fi
        ;;
    centos|rhel|rocky|alma)
        $INSTALL gcc gcc-c++ make pkgconfig openssl-devel curl git
        if [ "$NO_DESKTOP" = false ]; then
            warn "WebKitGTK 4.1 may not be available — desktop build may fail"
            $INSTALL gtk3-devel librsvg2-devel || true
        fi
        ;;
    arch|manjaro|endeavouros)
        $INSTALL base-devel openssl curl git
        if [ "$NO_DESKTOP" = false ]; then
            $INSTALL webkit2gtk-4.1 libappindicator-gtk3 \
                     librsvg gtk3 patchelf
        fi
        ;;
    opensuse*|suse|sles)
        $INSTALL gcc gcc-c++ make pkg-config libopenssl-devel curl git
        if [ "$NO_DESKTOP" = false ]; then
            $INSTALL webkit2gtk3-devel libappindicator3-devel \
                     librsvg-devel gtk3-devel patchelf || true
        fi
        ;;
    *)
        warn "Cannot install system packages automatically."
        warn "Please install: gcc, make, pkg-config, openssl-dev, curl, git"
        ;;
esac
ok "System packages installed"

# --- 2. Rust toolchain ---
if [ "$NO_RUST" = false ]; then
    if command -v rustup &>/dev/null; then
        info "Rust toolchain found — updating..."
        rustup update nightly
        rustup default nightly
    else
        info "Installing Rust toolchain (nightly)..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi
    rustup component add clippy rustfmt
    ok "Rust $(rustc --version | awk '{print $2}') installed"
else
    info "Skipping Rust installation (--no-rust)"
fi

# --- 3. Node.js (for desktop) ---
if [ "$NO_DESKTOP" = false ]; then
    if command -v node &>/dev/null; then
        NODE_VER=$(node --version)
        info "Node.js $NODE_VER found"
    else
        info "Installing Node.js 20 LTS..."
        case "$DISTRO" in
            ubuntu|debian|linuxmint|pop)
                curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
                $INSTALL nodejs
                ;;
            fedora)
                $INSTALL nodejs npm
                ;;
            arch|manjaro|endeavouros)
                $INSTALL nodejs npm
                ;;
            *)
                warn "Install Node.js 20+ manually: https://nodejs.org"
                ;;
        esac
    fi

    if [ -f "$REPO_ROOT/desktop/package.json" ]; then
        info "Installing desktop frontend dependencies..."
        cd "$REPO_ROOT/desktop"
        npm ci 2>/dev/null || npm install
        cd "$REPO_ROOT"
        ok "Desktop frontend dependencies installed"
    fi
else
    info "Skipping desktop/Node.js setup (--no-desktop)"
fi

# --- 4. Python + AI dependencies ---
if [ "$NO_PYTHON" = false ]; then
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 --version | awk '{print $2}')
        info "Python $PY_VER found"
    else
        info "Installing Python 3..."
        case "$DISTRO" in
            ubuntu|debian|linuxmint|pop)
                $INSTALL python3 python3-pip python3-venv
                ;;
            fedora)
                $INSTALL python3 python3-pip python3-virtualenv
                ;;
            arch|manjaro|endeavouros)
                $INSTALL python python-pip python-virtualenv
                ;;
            *)
                warn "Install Python 3.11+ manually"
                ;;
        esac
    fi

    if [ -f "$REPO_ROOT/ai/pyproject.toml" ]; then
        info "Setting up Python AI environment..."
        cd "$REPO_ROOT/ai"
        if [ ! -d .venv ]; then
            python3 -m venv .venv
        fi
        # shellcheck disable=SC1091
        source .venv/bin/activate
        pip install -q --upgrade pip
        pip install -q -e ".[dev]"
        deactivate
        cd "$REPO_ROOT"
        ok "Python AI environment ready"
    fi
else
    info "Skipping Python setup (--no-python)"
fi

# --- Summary ---
echo ""
echo "=========================================="
info "OS-DEFENDER 2.0 dependency setup complete"
echo "=========================================="
echo ""
echo "  Build the project:"
echo "    cargo build --release"
echo ""
echo "  Run tests:"
echo "    cargo test && cargo clippy -- -D warnings"
echo ""
if [ "$NO_PYTHON" = false ]; then
echo "  Run AI tests:"
echo "    cd ai && source .venv/bin/activate && pytest && ruff check ."
echo ""
fi
if [ "$NO_DESKTOP" = false ]; then
echo "  Build desktop app:"
echo "    cd desktop && npx tauri build"
echo ""
fi
echo "  Install (Linux):"
echo "    ./installer/linux/install.sh"
echo ""
