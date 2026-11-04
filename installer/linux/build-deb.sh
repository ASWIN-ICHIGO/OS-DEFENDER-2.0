#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-2.0.0}"
ARCH="${ARCH:-amd64}"
PKG_NAME="os-defender"
PKG_DIR="$(mktemp -d)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/target/packages}"

echo "Building .deb package: ${PKG_NAME}_${VERSION}_${ARCH}.deb"

mkdir -p "$OUT_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/local/bin"
mkdir -p "$PKG_DIR/etc/os-defender"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/var/lib/os-defender"
mkdir -p "$PKG_DIR/var/lib/os-defender/quarantine"

# Control file
cat > "$PKG_DIR/DEBIAN/control" <<CTRL
Package: $PKG_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: Aswin <caswin548@gmail.com>
Description: OS-DEFENDER 2.0 — Offline-first AI-powered endpoint protection
 Real-time endpoint detection, prevention and response platform
 with native OS integration and offline-first AI capabilities.
Depends: libc6 (>= 2.31)
CTRL

# Post-install script
cat > "$PKG_DIR/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
systemctl daemon-reload
echo "OS-DEFENDER installed. Enable with: systemctl enable --now os-defender-agent"
POSTINST
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Pre-remove script
cat > "$PKG_DIR/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
systemctl stop os-defender-agent 2>/dev/null || true
systemctl disable os-defender-agent 2>/dev/null || true
PRERM
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Copy binaries
if [ -f "$REPO_ROOT/target/release/os-defender-agent" ]; then
    install -m 755 "$REPO_ROOT/target/release/os-defender-agent" "$PKG_DIR/usr/local/bin/"
    install -m 755 "$REPO_ROOT/target/release/os-defender" "$PKG_DIR/usr/local/bin/"
else
    echo "Error: release binaries not found. Run 'cargo build --release' first."
    rm -rf "$PKG_DIR"
    exit 1
fi

# Systemd service (system-wide variant)
cat > "$PKG_DIR/lib/systemd/system/os-defender-agent.service" <<'SVC'
[Unit]
Description=OS-DEFENDER Protection Agent
After=network.target
Documentation=https://github.com/ASWIN-ICHIGO/os-defender-2.0

[Service]
Type=simple
ExecStart=/usr/local/bin/os-defender-agent --db-path /var/lib/os-defender/os-defender.db --quarantine-dir /var/lib/os-defender/quarantine
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/os-defender
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVC

# Default config
cat > "$PKG_DIR/etc/os-defender/agent.toml" <<'TOML'
[agent]
poll_interval_ms = 2000
heartbeat_timeout_secs = 60
policy_mode = "dry_run"
watch_dirs = "/etc,/home"

[storage]
db_path = "/var/lib/os-defender/os-defender.db"

[quarantine]
dir = "/var/lib/os-defender/quarantine"
TOML

# Build
dpkg-deb --build "$PKG_DIR" "$OUT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

rm -rf "$PKG_DIR"
echo "Package built: $OUT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
