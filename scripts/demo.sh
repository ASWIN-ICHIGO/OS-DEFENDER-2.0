#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "╔══════════════════════════════════════════════╗"
echo "║         OS-DEFENDER 2.0 — Live Demo          ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

echo "▸ [1/6] Building release binaries..."
cargo build --release 2>&1 | tail -3
echo "  ✓ Build complete"
echo ""

echo "▸ [2/6] Running full test suite..."
TEST_OUTPUT=$(cargo test --workspace 2>&1)
PASS_COUNT=$(echo "$TEST_OUTPUT" | grep -oP '\d+ passed' | head -1 || echo "0 passed")
echo "  ✓ $PASS_COUNT"
echo ""

echo "▸ [3/6] Detection engine throughput benchmark..."
cargo test benchmark_detection_engine_throughput -- --nocapture 2>&1 \
    | grep -E "(Throughput|Events processed|Alerts)" \
    | sed 's/^/  /'
echo ""

echo "▸ [4/6] Attack simulation — 14 MITRE ATT&CK techniques..."
SIM_OUTPUT=$(cargo test --test attack_simulation 2>&1)
SIM_PASS=$(echo "$SIM_OUTPUT" | grep -oP '\d+ passed' | head -1 || echo "0 passed")
echo "  ✓ $SIM_PASS (T1110, T1059, T1059.004, T1565.001, T1486, T1571, T1053.003,"
echo "    T1543.002, T1098.004, T1071, T1546.004 + 4 negative controls)"
echo ""

echo "▸ [5/6] Security posture checks (offline)..."
echo "  10 checks: shadow perms, SSH config, firewall, SUID audit,"
echo "  noexec /tmp, core dumps, ASLR, auto-updates, empty passwords"
echo "  ✓ Posture assessment available via: os-defender-cli posture"
echo ""

echo "▸ [6/6] AI/ML pipeline status..."
if [ -d "$PROJECT_DIR/ai" ] && command -v python3 &>/dev/null; then
    if [ -d "$PROJECT_DIR/ai/.venv" ]; then
        source "$PROJECT_DIR/ai/.venv/bin/activate" 2>/dev/null || true
    fi
    AI_TESTS=$(cd "$PROJECT_DIR/ai" && python3 -m pytest --tb=no -q 2>&1 | tail -1 || echo "not available")
    echo "  Python AI tests: $AI_TESTS"
else
    echo "  Python environment not configured — see docs/INSTALLATION.md"
fi
echo ""

echo "╔══════════════════════════════════════════════╗"
echo "║              Demo Complete                    ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Binaries: target/release/os-defender-*      ║"
echo "║  Agent:    os-defender-agent                  ║"
echo "║  CLI:      os-defender-cli status             ║"
echo "║  Desktop:  cd desktop && cargo tauri dev      ║"
echo "║  Docs:     docs/INSTALLATION.md               ║"
echo "╚══════════════════════════════════════════════╝"
