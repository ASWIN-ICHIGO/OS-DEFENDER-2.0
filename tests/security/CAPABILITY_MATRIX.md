# Cross-Platform Capability Matrix — OS Defender 2.0

## Legend

- ✅ Implemented and tested
- ⚠️ Implemented, not tested on real hardware
- ❌ Not implemented

## Collection

| Feature | Linux | Windows | Notes |
|---|---|---|---|
| Process collection | ✅ `/proc` polling with PID diff | ⚠️ ToolHelp32 snapshot | Windows collector cfg-gated, untested on real Windows |
| File monitoring | ✅ inotify real-time | ⚠️ FindFirstChangeNotification | Windows watches subtree changes |
| Network monitoring | ✅ `/proc/net/tcp` parsing | ⚠️ GetExtendedTcpTable (TCP IPv4) | Windows limited to TCP IPv4; no UDP/IPv6 yet |
| Auth monitoring | ✅ journalctl streaming | ⚠️ Security Event Log (4624/4625/4634/4672) | Windows reads event IDs for logon/logoff/failed/escalation |
| System info | ✅ hostname + `/etc/machine-id` | ⚠️ Registry MachineGuid + GetComputerNameExW | |

## Detection

| Feature | Linux | Windows | Notes |
|---|---|---|---|
| R001 Brute-force | ✅ | ✅ | Same rule logic, cross-platform event parity tested |
| R002 Suspicious process | ✅ | ✅ | Same rule logic, cross-platform event parity tested |
| R003 File tampering | ✅ | ✅ | Same rule logic, cross-platform event parity tested |
| R004 Anomalous network | ✅ | ✅ | Same rule logic, cross-platform event parity tested |
| R005 Persistence change | ✅ | ✅ | Same rule logic, cross-platform event parity tested |
| R006 Ransomware defense | ✅ | ✅ | Canary files, entropy, rapid-mod/rename, extensions |
| Process tree tracking | ✅ Parent-child with cycle protection | ✅ Same logic | Tree built from ProcessContext data |
| AI anomaly scoring | ✅ IsolationForest ONNX | ✅ IsolationForest ONNX | Python sidecar, cross-platform ONNX Runtime |
| Baseline drift detection | ✅ Z-score | ✅ Z-score | Profile save/load, per-feature z-scores |
| Local LLM explanations | ✅ Ollama (optional) | ✅ Ollama (optional) | Graceful fallback when unavailable |

## Prevention / Enforcement

| Feature | Linux | Windows | Notes |
|---|---|---|---|
| IP blocking | ✅ nftables (comment-tagged rules) | ⚠️ WFP via netsh advfirewall | Windows uses CLI wrapper; direct WFP API deferred |
| IP unblocking (rollback) | ✅ nftables rule removal | ⚠️ netsh advfirewall delete | Token-based rollback |
| Process freeze | ✅ cgroup v2 freeze/thaw | ⚠️ Job Object + SuspendThread | Safety: refuses PID ≤ 2 |
| Process thaw (rollback) | ✅ cgroup v2 thaw | ⚠️ ResumeThread | |
| File quarantine | ✅ Move + SHA-256 | ✅ Move + SHA-256 | Cross-platform module, same code |
| File restore (rollback) | ✅ Integrity-verified restore | ✅ Integrity-verified restore | SHA-256 check before restore |
| Policy engine | ✅ dry_run/approve/execute | ✅ dry_run/approve/execute | Severity-based auto-execute in approve mode |
| Hash-chained audit log | ✅ SHA-256 chain | ✅ SHA-256 chain | Tamper detection via chain verification |

## Advanced Security Modules

| Feature | Linux | Windows | Notes |
|---|---|---|---|
| Ransomware canary files | ✅ | ✅ | Deploy, verify, detect tamper/deletion |
| Persistence scanner | ✅ systemd, cron, shell rc, init.d, XDG, udev | ⚠️ Registry Run, startup folder, scheduled tasks | Windows scanner cfg-gated, untested on real Windows |
| File intelligence | ✅ SHA-256, reputation DB, IOC lists | ✅ SHA-256, reputation DB, IOC lists | In-memory DB, not persisted to SQLite |
| Threat hunting | ✅ SQL-backed queries | ✅ SQL-backed queries | Filters: type, severity, time, process, file, network, auth, payload text |
| Digital forensics | ✅ Timeline, evidence, reports | ✅ Timeline, evidence, reports | JSON export; PDF not yet implemented |
| Security posture | ✅ 10 hardening checks | ❌ | Linux-only: shadow perms, SSH config, firewall, SUID, noexec, ASLR, updates, empty passwords |
| Tamper protection | ✅ Manifest + signed config | ✅ Manifest + signed config | SHA-256 integrity verification |

## Infrastructure

| Feature | Linux | Windows | Notes |
|---|---|---|---|
| IPC (agent ↔ CLI/desktop) | ✅ Unix domain socket | ⚠️ Named pipes (planned) | Currently Unix sockets only; Windows IPC not yet wired |
| Storage (SQLite) | ✅ WAL mode | ✅ WAL mode | rusqlite with bundled SQLite |
| systemd service | ✅ | N/A | Service definition in config/ |
| Desktop application | ✅ Tauri v2 | ⚠️ Tauri v2 | Cross-platform; untested on Windows |

## Test Coverage

| Category | Count | Notes |
|---|---|---|
| Core library unit tests | 128 | All modules: events, detection, advanced, response, health |
| Cross-platform parity tests | 9 | All detection rules fire identically on Linux and Windows events |
| Enforcement integration tests | 13 | Policy modes, dry-run enforcement, quarantine round-trip, audit chain |
| Python AI tests | 41 | Feature extraction, IsolationForest, ONNX, drift, explainer, Ollama |
| **Total** | **191** | |
