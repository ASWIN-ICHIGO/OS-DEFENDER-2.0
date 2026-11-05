#!/usr/bin/env bash
# Integration test for the installer pipeline scripts.
# Validates that all scripts exist, are executable, and have correct syntax.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

echo "=== Installer Pipeline Integration Tests ==="

# --- Test: scripts exist and are executable ---
echo ""
echo "--- Script existence and permissions ---"
for script in \
    scripts/setup-deps.sh \
    scripts/setup-ai.sh \
    scripts/build-release.sh \
    scripts/sign-binary.sh \
    scripts/verify-signature.sh \
    scripts/generate-signing-keys.sh \
    installer/linux/install.sh \
    installer/linux/uninstall.sh \
    installer/linux/build-deb.sh \
    installer/linux/build-rpm.sh; do
    if [ -f "$REPO_ROOT/$script" ]; then
        if [ -x "$REPO_ROOT/$script" ]; then
            pass "$script exists and is executable"
        else
            fail "$script exists but is NOT executable"
        fi
    else
        fail "$script does not exist"
    fi
done

# --- Test: Windows scripts exist ---
echo ""
echo "--- Windows script existence ---"
for script in \
    scripts/setup-deps.ps1 \
    installer/windows/install.ps1 \
    installer/windows/uninstall.ps1 \
    installer/windows/os-defender.nsi; do
    if [ -f "$REPO_ROOT/$script" ]; then
        pass "$script exists"
    else
        fail "$script does not exist"
    fi
done

# --- Test: bash syntax ---
echo ""
echo "--- Shell script syntax ---"
for script in \
    scripts/setup-deps.sh \
    scripts/setup-ai.sh \
    scripts/build-release.sh \
    installer/linux/install.sh \
    installer/linux/uninstall.sh \
    installer/linux/build-deb.sh \
    installer/linux/build-rpm.sh; do
    if bash -n "$REPO_ROOT/$script" 2>/dev/null; then
        pass "$script syntax valid"
    else
        fail "$script has syntax errors"
    fi
done

# --- Test: setup-deps.sh has distro detection ---
echo ""
echo "--- Feature checks ---"
if grep -q "detect_distro" "$REPO_ROOT/scripts/setup-deps.sh"; then
    pass "setup-deps.sh has distro detection"
else
    fail "setup-deps.sh missing distro detection"
fi

for pm in "apt-get" "dnf" "pacman" "zypper"; do
    if grep -q "$pm" "$REPO_ROOT/scripts/setup-deps.sh"; then
        pass "setup-deps.sh supports $pm"
    else
        fail "setup-deps.sh missing $pm support"
    fi
done

if grep -q "rustup" "$REPO_ROOT/scripts/setup-deps.sh"; then
    pass "setup-deps.sh installs Rust toolchain"
else
    fail "setup-deps.sh missing Rust installation"
fi

if grep -q "python3" "$REPO_ROOT/scripts/setup-deps.sh"; then
    pass "setup-deps.sh installs Python"
else
    fail "setup-deps.sh missing Python installation"
fi

if grep -q "node" "$REPO_ROOT/scripts/setup-deps.sh"; then
    pass "setup-deps.sh handles Node.js for desktop"
else
    fail "setup-deps.sh missing Node.js setup"
fi

# --- Test: setup-deps.ps1 has required components ---
if grep -q "winget" "$REPO_ROOT/scripts/setup-deps.ps1"; then
    pass "setup-deps.ps1 uses winget"
else
    fail "setup-deps.ps1 missing winget support"
fi

if grep -q "VisualStudio" "$REPO_ROOT/scripts/setup-deps.ps1"; then
    pass "setup-deps.ps1 installs VC++ Build Tools"
else
    fail "setup-deps.ps1 missing VC++ Build Tools"
fi

# --- Test: build-release.sh produces packages ---
if grep -q "build-deb" "$REPO_ROOT/scripts/build-release.sh"; then
    pass "build-release.sh builds .deb packages"
else
    fail "build-release.sh missing .deb build"
fi

if grep -q "build-rpm" "$REPO_ROOT/scripts/build-release.sh"; then
    pass "build-release.sh builds RPM spec"
else
    fail "build-release.sh missing RPM build"
fi

if grep -q "sha256sum" "$REPO_ROOT/scripts/build-release.sh"; then
    pass "build-release.sh computes checksums"
else
    fail "build-release.sh missing checksum computation"
fi

if grep -q "sign-binary" "$REPO_ROOT/scripts/build-release.sh"; then
    pass "build-release.sh signs binaries"
else
    fail "build-release.sh missing binary signing"
fi

# --- Test: CI workflow has all required jobs ---
echo ""
echo "--- CI workflow checks ---"
WORKFLOW="$REPO_ROOT/.github/workflows/package.yml"
for job in "build-linux" "build-windows" "build-linux-desktop" "build-windows-desktop" "build-ai" "release"; do
    if grep -q "$job" "$WORKFLOW"; then
        pass "package.yml has $job job"
    else
        fail "package.yml missing $job job"
    fi
done

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
