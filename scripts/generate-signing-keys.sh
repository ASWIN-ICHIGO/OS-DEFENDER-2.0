#!/usr/bin/env bash
# Generate Ed25519 signing keypair for OS-DEFENDER binary signing.
# Private key → keep secret (CI secret / local vault).
# Public key → ships with the agent for signature verification.
set -euo pipefail

KEY_DIR="${1:-keys}"
mkdir -p "$KEY_DIR"

PRIV="$KEY_DIR/os-defender-signing.key"
PUB="$KEY_DIR/os-defender-signing.pub"

if [ -f "$PRIV" ]; then
    echo "ERROR: $PRIV already exists — refusing to overwrite."
    exit 1
fi

openssl genpkey -algorithm Ed25519 -out "$PRIV"
openssl pkey -in "$PRIV" -pubout -out "$PUB"

chmod 600 "$PRIV"
chmod 644 "$PUB"

echo ""
echo "Keys generated:"
echo "  Private: $PRIV  (keep secret — add as CI secret SIGNING_PRIVATE_KEY)"
echo "  Public:  $PUB  (ship with binaries)"
echo ""
echo "To sign a binary:"
echo "  openssl pkeyutl -sign -inkey $PRIV -rawin -in <(sha256sum binary | awk '{print \$1}') -out binary.sig"
echo ""
echo "To verify:"
echo "  openssl pkeyutl -verify -pubin -inkey $PUB -rawin -in <(sha256sum binary | awk '{print \$1}') -sigfile binary.sig"
echo ""

# Also generate a Tauri-compatible signing keypair for the desktop updater
echo "Generating Tauri updater keypair..."
TAURI_PRIV="$KEY_DIR/tauri-updater.key"
TAURI_PUB="$KEY_DIR/tauri-updater.pub"

if [ -f "$TAURI_PRIV" ]; then
    echo "WARNING: $TAURI_PRIV already exists — skipping Tauri key generation."
else
    openssl genpkey -algorithm Ed25519 -out "$TAURI_PRIV"
    openssl pkey -in "$TAURI_PRIV" -pubout -out "$TAURI_PUB"
    chmod 600 "$TAURI_PRIV"
    chmod 644 "$TAURI_PUB"
    echo "  Tauri private: $TAURI_PRIV  (set as TAURI_SIGNING_PRIVATE_KEY in CI)"
    echo "  Tauri public:  $TAURI_PUB  (set as pubkey in tauri.conf.json updater config)"
fi
