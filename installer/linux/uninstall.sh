#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/os-defender"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/os-defender"
SERVICE_DIR="$HOME/.config/systemd/user"

echo "OS-DEFENDER 2.0 — Linux Uninstaller"
echo "======================================"

if [ "$(id -u)" -eq 0 ]; then
    SERVICE_DIR="/etc/systemd/system"
    systemctl stop os-defender-agent 2>/dev/null || true
    systemctl disable os-defender-agent 2>/dev/null || true
else
    systemctl --user stop os-defender-agent 2>/dev/null || true
    systemctl --user disable os-defender-agent 2>/dev/null || true
fi

echo "Removing service file"
rm -f "$SERVICE_DIR/os-defender-agent.service"

echo "Removing binaries"
rm -f "$INSTALL_DIR/os-defender-agent"
rm -f "$INSTALL_DIR/os-defender"

echo "Removing config"
rm -rf "$CONFIG_DIR"

echo ""
echo "Uninstall complete."
echo "Data directory preserved at: $DATA_DIR"
echo "Remove manually with: rm -rf $DATA_DIR"
