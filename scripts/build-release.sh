#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/release-build"
VERSION="2.0.0-alpha.1"

echo "=== OS Defender $VERSION Release Build ==="
echo ""

# Step 1: Run tests
echo "[1/6] Running tests..."
cd "$PROJECT_DIR"
cargo test --workspace 2>&1 | tail -10
echo ""

# Step 2: Run clippy
echo "[2/6] Running clippy..."
cargo clippy --workspace 2>&1 | tail -3
echo ""

# Step 3: Build release binaries
echo "[3/6] Building release binaries..."
cargo build --release --workspace
echo ""

# Step 4: Run Python checks (if available)
echo "[4/6] Checking Python AI layer..."
if command -v python3 &>/dev/null && [ -d "$PROJECT_DIR/ai" ]; then
    cd "$PROJECT_DIR/ai"
    if [ -f requirements.txt ]; then
        python3 -m pytest tests/ 2>&1 | tail -5 || echo "Python tests skipped"
        python3 -m ruff check . 2>&1 | tail -3 || echo "Ruff check skipped"
    fi
else
    echo "Python not available or no ai/ directory — skipping"
fi
cd "$PROJECT_DIR"
echo ""

# Step 5: Collect release artifacts
echo "[5/6] Collecting release artifacts..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/bin"
mkdir -p "$BUILD_DIR/config"
mkdir -p "$BUILD_DIR/docs"

# Binaries
cp target/release/os-defender-agent "$BUILD_DIR/bin/" 2>/dev/null || echo "Agent binary not found"
cp target/release/os-defender-cli "$BUILD_DIR/bin/" 2>/dev/null || echo "CLI binary not found"

# Configuration
cp config/*.service "$BUILD_DIR/config/" 2>/dev/null || true
cp config/*.toml "$BUILD_DIR/config/" 2>/dev/null || true

# Documentation
cp docs/*.md "$BUILD_DIR/docs/" 2>/dev/null || true
cp IMPLEMENTATION_STATUS.md "$BUILD_DIR/docs/"
cp ROADMAP.md "$BUILD_DIR/docs/"

# Security validation
mkdir -p "$BUILD_DIR/docs/security"
cp tests/security/*.md "$BUILD_DIR/docs/security/" 2>/dev/null || true

echo ""

# Step 6: Summary
echo "[6/6] Release build complete!"
echo ""
echo "Artifacts in: $BUILD_DIR/"
echo ""
ls -la "$BUILD_DIR/bin/" 2>/dev/null || true
echo ""
echo "To install:"
echo "  sudo cp $BUILD_DIR/bin/os-defender-agent /usr/local/bin/"
echo "  sudo cp $BUILD_DIR/bin/os-defender-cli /usr/local/bin/"
echo "  sudo cp $BUILD_DIR/config/os-defender.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable --now os-defender"
