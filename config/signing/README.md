# OS-DEFENDER Code Signing

## Overview

OS-DEFENDER uses Ed25519 signatures to verify binary integrity.

## Key Management

1. **Generate keys** (do this once, on a trusted machine):
   ```bash
   ./scripts/generate-signing-keys.sh keys/
   ```

2. **Store the private key** as a GitHub Actions secret:
   - Name: `SIGNING_PRIVATE_KEY`
   - Value: contents of `keys/os-defender-signing.key`

3. **Store the Tauri updater key** as a GitHub Actions secret:
   - Name: `TAURI_SIGNING_PRIVATE_KEY`
   - Value: contents of `keys/tauri-updater.key`

4. **Ship the public key** with the distribution:
   - Copy `keys/os-defender-signing.pub` to `config/signing/os-defender-signing.pub`
   - Set the Tauri public key in `desktop/src-tauri/tauri.conf.json` updater config

## Verification

```bash
./scripts/verify-signature.sh /usr/local/bin/os-defender-agent config/signing/os-defender-signing.pub
```

## CI Behavior

- When `SIGNING_PRIVATE_KEY` secret is set: binaries are signed automatically
- When not set: binaries are built without signatures (development builds)
- Checksums (SHA256) are always generated for all platforms
