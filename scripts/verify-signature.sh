#!/usr/bin/env bash
# Verify an OS-DEFENDER binary signature.
# Usage: verify-signature.sh <binary> <public-key>
set -euo pipefail

BINARY="$1"
PUBLIC_KEY="$2"
SIG_FILE="${BINARY}.sig"
CHECKSUM_FILE="${BINARY}.sha256"

if [ ! -f "$BINARY" ]; then
    echo "FAIL: binary not found: $BINARY" >&2
    exit 1
fi
if [ ! -f "$SIG_FILE" ]; then
    echo "FAIL: signature not found: $SIG_FILE" >&2
    exit 1
fi

# Verify checksum matches
ACTUAL_HASH=$(sha256sum "$BINARY" | awk '{print $1}')
if [ -f "$CHECKSUM_FILE" ]; then
    EXPECTED_HASH=$(cat "$CHECKSUM_FILE")
    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        echo "FAIL: checksum mismatch" >&2
        echo "  Expected: $EXPECTED_HASH" >&2
        echo "  Actual:   $ACTUAL_HASH" >&2
        exit 1
    fi
    echo "Checksum: OK"
fi

# Verify Ed25519 signature over the hash
echo -n "$ACTUAL_HASH" | openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -rawin -sigfile "$SIG_FILE"
