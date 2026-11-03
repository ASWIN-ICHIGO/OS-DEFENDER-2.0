# OS-DEFENDER 2.0 — Security Design

## Principles

1. **Least privilege**: Each component operates with minimum necessary permissions
2. **Defense in depth**: Multiple detection methods, multiple enforcement layers
3. **Dry-run by default**: No enforcement action executes without explicit approval
4. **Audit everything**: Hash-chained log for all security-relevant actions
5. **Fail safe**: Degraded protection is visible, not silent

## Authentication and Authorization

### IPC Security
- Unix domain socket with file permissions (mode 0600, owner-only)
- JSON-line protocol with strict schema validation
- No TCP/UDP network exposure by default
- Desktop app connects as the same user — no cross-user access

### Policy Engine
- All response actions require a matching policy
- Policies are versioned and signed (planned)
- Approval workflow: propose → human review → approve → execute
- Approval TTL: approved actions expire if not executed promptly

## Data Security

### Event Data
- Process names, filenames, network metadata treated as untrusted input
- No secrets stored in event payloads — redaction at collection time
- SQLite WAL mode with bounded growth
- Configurable retention period

### Audit Log
- Append-only with hash chaining
- Each entry contains: timestamp, action, target, actor, reason, previous hash
- Integrity verification on startup
- Protected against casual tampering (not against root-level modification)

### AI Models
- Model files verified by SHA-256 hash before loading
- No pickled Python models (arbitrary code execution risk)
- ONNX format only for inference models
- LLM outputs treated as untrusted — never used for enforcement decisions

## Enforcement Safety

### Process Containment
- Protected PID list (init, kernel threads, agent's own tree)
- cgroups freeze (not SIGKILL) — reversible
- Rollback always available
- System-critical processes never targeted automatically

### File Quarantine
- Copy-verify-delete with SHA-256 integrity check
- Restore path with collision detection
- Quarantine vault with restricted permissions
- Protected directories (/, /usr, /boot) cannot be quarantined

### Network Enforcement
- nftables rules with named chains (easy identification and removal)
- Temporary blocks with automatic expiry
- Rollback by rule deletion
- Agent's own network traffic exempted

## Known Weaknesses

1. Root-level attacker can modify agent binary, config, or audit log
2. User-space inotify has a watch limit — an attacker filling it creates blind spots
3. /proc-based process monitoring can miss very short-lived processes
4. journalctl streaming may lag under high system load
5. SQLite is not crash-proof against hardware failure without synchronous=FULL
