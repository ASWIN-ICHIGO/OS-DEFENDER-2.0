# OS-DEFENDER 2.0 — Testing Strategy

## Test Levels

### Unit Tests (Rust)
- Location: `#[cfg(test)]` modules in each source file
- Run: `cargo test`
- Coverage: event schema, parsing, detection rules, storage CRUD, health monitoring
- No elevated privileges required

### Unit Tests (Python AI)
- Location: `ai/tests/`
- Run: `cd ai && pytest`
- Coverage: feature extraction, model training, inference correctness

### Integration Tests
- Location: `tests/integration/`
- Run: `cargo test --test '*'` (requires agent running)
- Coverage: collector → detection → storage pipeline, IPC protocol, CLI commands

### Security Tests
- Location: `tests/security/`
- Coverage: IPC authentication, input validation, redaction, audit log integrity
- Includes hostile input testing (malformed events, injection attempts)

### Simulation Tests
- Location: `tests/simulation/`
- Coverage: harmless attack scenarios, expected detection verification
- MITRE ATT&CK technique mapping per scenario

### Platform Tests
- Linux: run on EndeavourOS with real /proc, inotify, journalctl
- Windows: run on Windows 10/11 with real ETW, Event Log, WFP
- Cross-platform: verify event schema parity between platforms

## Test Infrastructure

### Rust
```bash
# All unit tests
cargo test

# Specific crate
cargo test -p os-defender-core

# With output
cargo test -- --nocapture

# Specific test
cargo test events::tests::event_serialization_roundtrip
```

### Linting
```bash
# Rust
cargo clippy -- -D warnings

# Python
cd ai && ruff check .
```

## Performance Testing

Measure on the target hardware (AMD Ryzen 5 7530U, 12GB RAM):
- Idle CPU usage of agent
- RSS memory of agent
- Event processing latency (event → alert time)
- Storage write throughput
- IPC round-trip time

## What We Never Do

- Run real malware
- Attack external machines
- Use uncontrolled network attacks
- Execute destructive OS operations outside isolated test environments
- Fabricate test results or performance metrics
