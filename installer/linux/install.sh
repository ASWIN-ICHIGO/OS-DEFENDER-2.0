#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/os-defender"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/os-defender"
SERVICE_DIR="$HOME/.config/systemd/user"

echo "OS-DEFENDER 2.0 — Linux Installer"
echo "==================================="

if [ "$(id -u)" -eq 0 ]; then
    echo "Warning: running as root. Agent will install system-wide."
    INSTALL_DIR="/usr/local/bin"
    SERVICE_DIR="/etc/systemd/system"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Installing binaries to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
install -m 755 "$REPO_ROOT/target/release/os-defender-agent" "$INSTALL_DIR/"
install -m 755 "$REPO_ROOT/target/release/os-defender" "$INSTALL_DIR/"

echo "Creating data directory: $DATA_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/quarantine"

echo "Creating config directory: $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/agent.toml" ]; then
    cat > "$CONFIG_DIR/agent.toml" <<'TOML'
[agent]
poll_interval_ms = 2000
heartbeat_timeout_secs = 60
policy_mode = "dry_run"
watch_dirs = "/etc,/home"

[storage]
db_path = "~/.local/share/os-defender/os-defender.db"

[quarantine]
dir = "~/.local/share/os-defender/quarantine"
TOML
fi

echo "Installing systemd service"
mkdir -p "$SERVICE_DIR"
if [ "$(id -u)" -eq 0 ]; then
    sed 's|%h/.cargo/bin/|/usr/local/bin/|g' \
        "$REPO_ROOT/config/os-defender-agent.service" \
        > "$SERVICE_DIR/os-defender-agent.service"
    systemctl daemon-reload
    echo "Enable with: systemctl enable --now os-defender-agent"
else
    cp "$REPO_ROOT/config/os-defender-agent.service" "$SERVICE_DIR/"
    systemctl --user daemon-reload
    echo "Enable with: systemctl --user enable --now os-defender-agent"
fi

echo ""
echo "Installation complete."
echo "  Agent binary:  $INSTALL_DIR/os-defender-agent"
echo "  CLI binary:    $INSTALL_DIR/os-defender"
echo "  Data:          $DATA_DIR"
echo "  Config:        $CONFIG_DIR"
