#!/usr/bin/env bash
# OS-DEFENDER 2.0 — Production release build pipeline.
# Builds all components, runs all tests, produces installable packages.
# Usage: ./scripts/build-release.sh [--skip-tests] [--skip-desktop] [--skip-ai]
set -euo pipefail

SKIP_TESTS=false
SKIP_DESKTOP=false
SKIP_AI=false
for arg in "$@"; do
    case "$arg" in
        --skip-tests)   SKIP_TESTS=true ;;
        --skip-desktop) SKIP_DESKTOP=true ;;
        --skip-ai)      SKIP_AI=true ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/release-build"
VERSION="${VERSION:-2.0.0}"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"
STEPS=0
TOTAL=8

info()  { STEPS=$((STEPS+1)); echo -e "\n\033[1;34m[$STEPS/$TOTAL]\033[0m $*"; }
ok()    { echo -e "\033[1;32m  ✓\033[0m $*"; }
fail()  { echo -e "\033[1;31m  ✗\033[0m $*"; exit 1; }

cd "$PROJECT_DIR"

echo "=== OS-DEFENDER $VERSION — Production Release Build ==="

# --- 1. Verify dependencies ---
info "Verifying build dependencies..."
command -v cargo   >/dev/null || fail "cargo not found — run scripts/setup-deps.sh"
command -v rustc   >/dev/null || fail "rustc not found"
if [ "$SKIP_DESKTOP" = false ]; then
    command -v node  >/dev/null || fail "node not found — run scripts/setup-deps.sh or use --skip-desktop"
    command -v npm   >/dev/null || fail "npm not found"
fi
if [ "$SKIP_AI" = false ]; then
    command -v python3 >/dev/null || fail "python3 not found — run scripts/setup-deps.sh or use --skip-ai"
fi
ok "Dependencies verified"

# --- 2. Rust tests + clippy ---
if [ "$SKIP_TESTS" = false ]; then
    info "Running Rust tests..."
    cargo test --workspace 2>&1 | tail -20
    ok "Rust tests passed"

    cargo clippy --workspace -- -D warnings 2>&1 | tail -5
    ok "Clippy clean"
else
    info "Skipping tests (--skip-tests)"
fi

# --- 3. Build release binaries ---
info "Building release binaries..."
cargo build --release --workspace
ok "Agent: $(ls -sh target/release/os-defender-agent 2>/dev/null | awk '{print $1}')"
ok "CLI:   $(ls -sh target/release/os-defender 2>/dev/null | awk '{print $1}')"

# --- 4. Python AI tests ---
if [ "$SKIP_AI" = false ] && [ -d "$PROJECT_DIR/ai" ]; then
    info "Running Python AI tests..."
    cd "$PROJECT_DIR/ai"
    if [ -d .venv ]; then
        # shellcheck disable=SC1091
        source .venv/bin/activate
    fi
    python3 -m pytest tests/ 2>&1 | tail -10
    python3 -m ruff check . 2>&1 | tail -3
    if [ -d .venv ]; then deactivate; fi
    cd "$PROJECT_DIR"
    ok "Python AI tests passed"
else
    info "Skipping AI tests"
fi

# --- 5. Build desktop app ---
if [ "$SKIP_DESKTOP" = false ] && [ -d "$PROJECT_DIR/desktop" ]; then
    info "Building desktop application..."
    cd "$PROJECT_DIR/desktop"
    npm ci 2>/dev/null || npm install
    npx tauri build --ci 2>&1 | tail -15
    cd "$PROJECT_DIR"
    ok "Desktop app built"
else
    info "Skipping desktop build"
fi

# --- 6. Collect release artifacts ---
info "Collecting release artifacts..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{bin,config,docs,ai,installer}

cp target/release/os-defender-agent "$BUILD_DIR/bin/" 2>/dev/null || fail "Agent binary not found"
cp target/release/os-defender "$BUILD_DIR/bin/" 2>/dev/null || fail "CLI binary not found"

cp config/*.service "$BUILD_DIR/config/" 2>/dev/null || true
cp config/*.toml "$BUILD_DIR/config/" 2>/dev/null || true

cp docs/*.md "$BUILD_DIR/docs/" 2>/dev/null || true
cp ROADMAP.md "$BUILD_DIR/docs/" 2>/dev/null || true

if [ "$SKIP_AI" = false ] && [ -d ai ]; then
    cp -r ai/src "$BUILD_DIR/ai/src" 2>/dev/null || true
    cp ai/pyproject.toml "$BUILD_DIR/ai/" 2>/dev/null || true
fi

cp installer/linux/install.sh "$BUILD_DIR/installer/" 2>/dev/null || true
cp installer/linux/uninstall.sh "$BUILD_DIR/installer/" 2>/dev/null || true
cp scripts/setup-deps.sh "$BUILD_DIR/installer/" 2>/dev/null || true

if [ "$SKIP_DESKTOP" = false ]; then
    mkdir -p "$BUILD_DIR/desktop"
    cp desktop/src-tauri/target/release/bundle/deb/*.deb "$BUILD_DIR/desktop/" 2>/dev/null || true
    cp desktop/src-tauri/target/release/bundle/appimage/*.AppImage "$BUILD_DIR/desktop/" 2>/dev/null || true
fi

# SHA256 checksums
cd "$BUILD_DIR/bin"
sha256sum os-defender-agent > os-defender-agent.sha256
sha256sum os-defender > os-defender.sha256
cd "$PROJECT_DIR"

ok "Artifacts collected in $BUILD_DIR/"

# --- 7. Build Linux packages ---
info "Building Linux packages..."
mkdir -p "$BUILD_DIR/packages"

if command -v dpkg-deb &>/dev/null; then
    VERSION="$VERSION" ARCH="$ARCH" OUT_DIR="$BUILD_DIR/packages" \
        bash installer/linux/build-deb.sh
    ok ".deb package built"
else
    echo "  dpkg-deb not found — skipping .deb"
fi

VERSION="$VERSION" OUT_DIR="$BUILD_DIR/packages" \
    bash installer/linux/build-rpm.sh
ok "RPM spec generated"

# --- 8. Sign binaries (if key available) ---
info "Signing binaries..."
if [ -f config/signing/private.pem ]; then
    bash scripts/sign-binary.sh "$BUILD_DIR/bin/os-defender-agent" config/signing/private.pem
    bash scripts/sign-binary.sh "$BUILD_DIR/bin/os-defender" config/signing/private.pem
    ok "Binaries signed"
else
    echo "  No signing key found — skipping (see scripts/generate-signing-keys.sh)"
fi

# --- Summary ---
echo ""
echo "==========================================="
echo -e "\033[1;32m  OS-DEFENDER $VERSION release build complete\033[0m"
echo "==========================================="
echo ""
echo "  release-build/"
find "$BUILD_DIR" -type f | sort | while read -r f; do
    SIZE=$(ls -sh "$f" | awk '{print $1}')
    echo "    ${f#$BUILD_DIR/}  ($SIZE)"
done
echo ""
echo "  Install:"
echo "    Linux:    sudo ./release-build/installer/install.sh"
echo "    Desktop:  release-build/desktop/*.deb or *.AppImage"
echo ""
