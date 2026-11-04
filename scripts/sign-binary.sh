#!/usr/bin/env bash
# Sign an OS-DEFENDER binary with Ed25519.
# Usage: sign-binary.sh <binary> <private-key>
# Outputs: <binary>.sha256 and <binary>.sig
set -euo pipefail

BINARY="$1"
PRIVATE_KEY="$2"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: binary not found: $BINARY" >&2
    exit 1
fi
if [ ! -f "$PRIVATE_KEY" ]; then
    echo "ERROR: private key not found: $PRIVATE_KEY" >&2
    exit 1
fi

CHECKSUM_FILE="${BINARY}.sha256"
SIG_FILE="${BINARY}.sig"

sha256sum "$BINARY" | awk '{print $1}' > "$CHECKSUM_FILE"
HASH=$(cat "$CHECKSUM_FILE")

echo -n "$HASH" | openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -rawin -out "$SIG_FILE"

echo "Signed: $BINARY"
echo "  Checksum: $CHECKSUM_FILE ($HASH)"
echo "  Signature: $SIG_FILE"
