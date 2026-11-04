#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-2.0.0}"
RELEASE="${RELEASE:-1}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/target/packages}"

echo "Building RPM spec for os-defender $VERSION"

mkdir -p "$OUT_DIR"

SPEC_FILE="$OUT_DIR/os-defender.spec"

cat > "$SPEC_FILE" <<SPEC
Name:           os-defender
Version:        $VERSION
Release:        ${RELEASE}%{?dist}
Summary:        Offline-first AI-powered endpoint protection
License:        MIT
URL:            https://github.com/ASWIN-ICHIGO/os-defender-2.0

%description
OS-DEFENDER 2.0 is an offline-first AI-powered cross-platform endpoint
detection, prevention and response platform with native OS integration.

%install
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/etc/os-defender
mkdir -p %{buildroot}/lib/systemd/system
mkdir -p %{buildroot}/var/lib/os-defender/quarantine

install -m 755 $REPO_ROOT/target/release/os-defender-agent %{buildroot}/usr/local/bin/
install -m 755 $REPO_ROOT/target/release/os-defender %{buildroot}/usr/local/bin/
install -m 644 $SCRIPT_DIR/systemd-system.service %{buildroot}/lib/systemd/system/os-defender-agent.service

cat > %{buildroot}/etc/os-defender/agent.toml <<'TOML'
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

%files
/usr/local/bin/os-defender-agent
/usr/local/bin/os-defender
/lib/systemd/system/os-defender-agent.service
%config(noreplace) /etc/os-defender/agent.toml
%dir /var/lib/os-defender
%dir /var/lib/os-defender/quarantine

%post
systemctl daemon-reload

%preun
systemctl stop os-defender-agent 2>/dev/null || true
systemctl disable os-defender-agent 2>/dev/null || true
SPEC

echo "RPM spec written: $SPEC_FILE"
echo "Build with: rpmbuild -bb $SPEC_FILE"
