# OS-DEFENDER 2.0 — Test Report

**Date:** 2026-11-03
**Platform:** Linux 6.18.58-1-lts (x86_64)
**Rust:** Edition 2024
**Python:** 3.11+

## Summary

| Suite | Tests | Pass | Fail | Skip |
|---|---|---|---|---|
| Rust unit tests | 132 | 132 | 0 | 0 |
| Rust integration (attack simulation) | 18 | 18 | 0 | 0 |
| Rust performance benchmarks | 5 | 5 | 0 | 0 |
| Windows cross-platform | 18 | 18 | 0 | 0 |
| Python AI/ML tests | 41 | 41 | 0 | 0 |
| **Total** | **214** | **214** | **0** | **0** |

Lint status:
- `cargo clippy`: 0 warnings
- `ruff check`: 0 issues

## Rust Test Results

### Core Library — Unit Tests

**Events module:**
- NormalizedEvent creation and builder pattern
- Severity ordering (Info < Low < Medium < High < Critical)
- All context types (Process, File, Network, Auth)
- Event serialization/deserialization (Serde JSON)

**Detection engine:**
- Rule registration and rule count
- Event processing pipeline
- Alert generation with correct fields
- Tick-based periodic checks
- Empty ruleset handling

**Detection rules (R001–R006):**

| Rule | Tests | Coverage |
|---|---|---|
| R001 Brute Force | 4 | Below threshold (no alert), at threshold (alert), cooldown reset, severity escalation |
| R002 Suspicious Process | 5 | Reverse shell, recon tools (nmap, nc), SUID abuse, benign process (negative), parent-child |
| R003 File Tampering | 4 | Sensitive file modify, sensitive file create, rapid modification (20 in 60s), benign /tmp file (negative) |
| R004 Anomalous Network | 4 | Backdoor port, uncommon port to public IP, standard port (negative), internal IP (negative) |
| R005 Persistence Change | 7 | systemd service, cron, bashrc, profile, init.d, XDG autostart, authorized_keys |
| R006 Ransomware | 3 | Canary file detection, known extension, rapid rename storm |

**Response engine:**
- Policy mode transitions (DryRun → Approve → Execute)
- Action suggestion by severity
- Auto-execute threshold
- Hash-chained audit log (insert, verify, tamper detection, recovery)
- Audit chain integrity verification

**Enforcement (Linux):**
- nftables: block, unblock, rollback (3 tests)
- cgroup: freeze, thaw, safety PID check, rollback (5 tests)
- Quarantine: move, restore, integrity verify, missing file, corrupt file (5 tests)

**Enforcement (Windows):**
- WFP: block, unblock via netsh (2 tests)
- Job Object: suspend, resume, safety PID ≤ 4 (3 tests)
- Cross-platform enforcement parity (13 tests)

**Storage:**
- SQLite open, in-memory open
- Event insert and retrieval
- Event count
- Events by type filter
- WAL mode verification

**Health:**
- Sensor heartbeat tracking
- Lag detection
- Drop counting
- Visibility assessment with blind spots

**IPC protocol:**
- Request serialization (all 13 types)
- Response serialization
- Socket path generation

**Advanced modules:**

| Module | Tests | Coverage |
|---|---|---|
| Ransomware | 3 | Canary deploy/verify, entropy detection, extension matching |
| Persistence | 3 | Linux scan (systemd, cron, rc), entry risk classification, deduplication |
| File Intelligence | 4 | SHA-256 hashing, reputation lookup, IOC list load, known-bad detection |
| Threat Hunting | 4 | Query by event type, by severity, by time range, combined filters |
| Forensics | 3 | Timeline build, evidence collection, report generation (text + JSON) |
| Posture | 3 | Check execution, score calculation, grade assignment (A–F) |
| Tamper Protection | 3 | Manifest creation, integrity verify (pass), tamper detection (fail) |

### Integration Tests — Attack Simulation

18 tests simulating 14 MITRE ATT&CK techniques:

| Test | Technique | Result |
|---|---|---|
| t1110_brute_force_ssh | T1110 | PASS — alerts at 5th failure, correct rule + MITRE |
| t1110_brute_force_multiple_users_isolated | T1110 | PASS — per-user isolation verified |
| t1059_004_reverse_shell | T1059.004 | PASS — `/dev/tcp` pattern detected, severity ≥ High |
| t1059_network_recon_nmap | T1059 | PASS — nmap flagged as suspicious process |
| t1565_001_shadow_tampering | T1565.001 | PASS — /etc/shadow modification detected |
| t1486_ransomware_rapid_modifications | T1486 | PASS — 20 rapid mods trigger Critical alert |
| t1486_rapid_rename_storm | T1486 | PASS — bulk renames with .encrypted extension |
| t1571_non_standard_port_4444 | T1571 | PASS — outbound to backdoor port detected |
| t1053_003_cron_modification | T1053.003 | PASS — crontab change triggers persistence alert |
| t1543_002_systemd_service_creation | T1543.002 | PASS — new .service file detected |
| t1098_004_authorized_keys_modification | T1098.004 | PASS — SSH key injection detected |
| t1071_c2_uncommon_port | T1071 | PASS — C2 beaconing pattern flagged |
| t1059_recon_tool_execution | T1059 | PASS — netcat execution detected |
| t1546_004_bashrc_modification | T1546.004 | PASS — shell config persistence detected |
| benign_ssh_login_no_alert | (negative) | PASS — successful login produces no alert |
| benign_process_no_alert | (negative) | PASS — normal `ls` produces no alert |
| benign_outbound_443_no_alert | (negative) | PASS — HTTPS traffic not flagged |
| benign_file_in_tmp_no_alert | (negative) | PASS — /tmp file creation not flagged |

### Performance Benchmarks

| Benchmark | Metric | Result | Threshold |
|---|---|---|---|
| Detection engine throughput | events/sec | ~90,000 | > 1,000 |
| Mixed attack workload | alert rate | Correctly identifies embedded attacks | > 0 alerts |
| SQLite storage throughput | inserts/sec | ~5,500 | N/A |
| Ransomware detection latency | per-event | ~13 μs | N/A |
| Hunting query performance | query time | ~5 ms (500 events, filtered to 50) | N/A |

Note: benchmarks run in debug mode. Release builds are significantly faster.

## Python AI/ML Test Results

### Feature Extraction (10 tests)
- Window creation from event batches
- All 17 feature dimensions computed correctly
- Empty event handling (zero vector)
- Feature normalization ranges
- Mixed event type processing

### Baseline Learning (8 tests)
- Mean/std computation per feature
- Save/load JSON profile
- Drift detection with configurable z-threshold
- Per-feature drift reports
- Edge cases: zero variance, single sample

### IsolationForest Training (10 tests)
- Model training with default parameters
- ONNX export and file verification
- Scaler JSON output
- Metadata generation (contamination, estimators, feature count)
- Reproducibility (fixed random_state)

### ONNX Inference (8 tests)
- Model loading from file
- Single event scoring
- Batch scoring
- Score extraction (anomaly_score field)
- Label extraction (normal vs anomaly)
- Invalid input handling

### Ollama Integration (3 tests)
- Connection test (graceful timeout)
- Fallback to rule-based explanation
- Alert summary generation without LLM

### Offline Verification (2 tests)
- End-to-end pipeline: events → features → train → ONNX → inference → explain
- No network calls during entire pipeline (verified)

## Security Documentation

### MITRE ATT&CK Mapping
Full mapping documented in `tests/security/MITRE_MAPPING.md`:
- 13 techniques with detection method, rule ID, and prevention capability

### Capability Matrix
Cross-platform parity documented in `tests/security/CAPABILITY_MATRIX.md`:
- Linux vs Windows feature comparison across all modules

### Threat Model
Documented in `tests/security/THREAT_MODEL.md`:
- 7 asset classes (event database, audit log, quarantine, config, AI models, IPC socket, binary)
- 4 threat actor profiles (external attacker, malware, insider, supply chain)
- 5 attack surfaces (IPC socket, filesystem, /proc, network, AI model)

## Known Limitations

1. **Windows code not tested on real Windows** — cross-compilation verified, but runtime testing requires a Windows environment
2. **Attack simulations use synthetic events** — not live OS-level triggers; validates detection logic, not collection
3. **AI sidecar not wired to agent** — returns default status; real-time scoring deferred
4. **Performance benchmarks in debug mode** — release builds expected to be 3-5x faster
5. **No end-to-end integration test with real OS events** — requires privileged execution
6. **False positive tuning** — requires production workload data collection

## Verification Commands

```bash
# Run all Rust tests
cargo test

# Run with output (see benchmark numbers)
cargo test -- --nocapture

# Run specific test suite
cargo test --test attack_simulation
cargo test --test performance

# Clippy lint check
cargo clippy -- -D warnings

# Python tests
cd ai && pytest -v

# Python lint
cd ai && ruff check .
```
