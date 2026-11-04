#!/usr/bin/env bash
set -euo pipefail

echo "OS-DEFENDER 2.0 — Cross-Platform Compilation Check"
echo "===================================================="

TARGETS=()
FAILED=()

check_target() {
    local target="$1"
    echo ""
    echo "--- Checking: $target ---"
    if rustup target list --installed | grep -q "^${target}$"; then
        if cargo check --target "$target" 2>&1; then
            echo "  PASS: $target"
            TARGETS+=("$target:pass")
        else
            echo "  FAIL: $target"
            TARGETS+=("$target:fail")
            FAILED+=("$target")
        fi
    else
        echo "  SKIP: $target (not installed)"
        echo "  Install with: rustup target add $target"
        TARGETS+=("$target:skip")
    fi
}

echo ""
echo "Step 1: Native build + test"
echo "----------------------------"
cargo build 2>&1
cargo test 2>&1
cargo clippy 2>&1
echo "  Native: PASS"

echo ""
echo "Step 2: Cross-compilation checks"
echo "---------------------------------"
check_target "x86_64-unknown-linux-gnu"
check_target "x86_64-pc-windows-msvc"
check_target "x86_64-pc-windows-gnu"

echo ""
echo "===================================================="
echo "Results:"
for entry in "${TARGETS[@]}"; do
    target="${entry%%:*}"
    status="${entry##*:}"
    case "$status" in
        pass) echo "  [PASS] $target" ;;
        fail) echo "  [FAIL] $target" ;;
        skip) echo "  [SKIP] $target" ;;
    esac
done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo "FAILURES: ${FAILED[*]}"
    exit 1
fi

echo ""
echo "All available targets passed."
