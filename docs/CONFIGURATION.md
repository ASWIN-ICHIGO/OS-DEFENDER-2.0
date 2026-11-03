# OS-DEFENDER 2.0 — Configuration Reference

## Agent Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `OS_DEFENDER_DATA_DIR` | `~/.local/share/os-defender` | Data directory for database, models, quarantine |
| `OS_DEFENDER_SOCKET` | `~/.local/share/os-defender/agent.sock` | IPC socket path |

### systemd Service

The service file is at `config/os-defender-agent.service`:

```ini
[Unit]
Description=OS Defender Security Agent
After=default.target

[Service]
Type=simple
ExecStart=%h/.cargo/bin/os-defender-agent
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/os-defender
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=default.target
```

Key security settings:
- `ProtectSystem=strict` — read-only `/usr`, `/boot`, `/etc`
- `ProtectHome=read-only` — can read home but only write to data dir
- `NoNewPrivileges=true` — prevents privilege escalation
- `MemoryDenyWriteExecute=true` — blocks W^X memory

## Policy Engine

### Policy Modes

| Mode | Behavior |
|---|---|
| `dry_run` | Log actions only, no enforcement (default) |
| `approve` | Queue actions for manual approval via CLI/desktop |
| `execute` | Auto-execute response actions above severity threshold |

Set via CLI:
```bash
os-defender-cli policy set dry_run
os-defender-cli policy set approve
os-defender-cli policy set execute
```

Set via IPC (desktop app or programmatic):
```json
{"SetPolicyMode": "Execute"}
```

### Response Actions

The policy engine suggests actions based on alert severity:

| Severity | Suggested Actions |
|---|---|
| Low | Log only |
| Medium | Log + monitor |
| High | Network block, process containment |
| Critical | Network block, process containment, file quarantine |

In `execute` mode, High and Critical severity actions are auto-executed.

## Detection Rules

### Built-in Rules

| Rule ID | Name | MITRE | Threshold / Config |
|---|---|---|---|
| R001 | Brute Force | T1110 | 5 failures in 300s window, per source IP |
| R002 | Suspicious Process | T1059, T1059.004 | Pattern match: reverse shells, recon tools, SUID abuse |
| R003 | File Tampering | T1565.001, T1486 | Sensitive paths + rapid modification (20 in 60s) |
| R004 | Anomalous Network | T1071, T1571 | Uncommon ports, backdoor ports (4444, 5555, 6666, 8888) |
| R005 | Persistence Change | T1053.003, T1543.002, T1546.004, T1574.006, T1098.004, T1547.001 | 14 file path patterns |
| R006 | Ransomware Defense | T1486 | Canary files, entropy, known extensions, rapid renames |

### R001 — Brute Force Detection

```
Threshold: 5 failed authentication attempts
Window: 300 seconds
Cooldown: 600 seconds after alert
Escalation: Severity increases with attempt count
Tracking: Per source IP address
```

### R002 — Suspicious Process Detection

Detects:
- Reverse shell patterns (`/dev/tcp`, `mkfifo`, `nc -e`)
- Reconnaissance tools (`nmap`, `masscan`, `nikto`, `sqlmap`)
- Network tools used suspiciously (`nc`, `ncat`, `socat`, `netcat`)
- SUID binary abuse
- Unusual parent-child relationships

### R003 — File Tampering Detection

Sensitive paths monitored:
- `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`
- `/etc/ssh/sshd_config`, `~/.ssh/authorized_keys`
- `/etc/ld.so.preload`, `/etc/ld.so.conf`
- `/etc/systemd/system/` (service files)

Ransomware indicator: 20+ modifications within 60 seconds in same directory.

### R004 — Anomalous Network Detection

Backdoor ports: 4444, 5555, 6666, 7777, 8888, 9999
Common ports (excluded): 22, 53, 80, 443, 993, 995, 8080, 8443

Triggers on outbound connections to public IPs on non-standard ports.

### R005 — Persistence Change Detection

14 persistence patterns monitored:
- systemd: `/etc/systemd/system/*.service`, `~/.config/systemd/user/`
- cron: `/etc/crontab`, `/var/spool/cron/`, `/etc/cron.d/`
- Shell: `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`
- Init: `/etc/init.d/`
- XDG: `~/.config/autostart/`
- SSH: `~/.ssh/authorized_keys`

### R006 — Ransomware Defense

Multi-signal detection:
- Canary file tampering/deletion
- High entropy file content (encrypted data)
- Known ransomware extensions (`.encrypted`, `.locked`, `.crypto`, etc.)
- Rapid rename storms (bulk file renaming)

## Collectors

### Linux Collectors

| Collector | Source | Poll Interval |
|---|---|---|
| Process | `/proc` filesystem | 2 seconds |
| File | inotify watches | Real-time (event-driven) |
| Network | `/proc/net/tcp`, `/proc/net/udp` | 5 seconds |
| Auth | `journalctl` streaming | Real-time (event-driven) |

### Windows Collectors

| Collector | Source | Poll Interval |
|---|---|---|
| Process | ToolHelp32 snapshot | 2 seconds |
| File | FindFirstChangeNotification | Real-time (event-driven) |
| Network | GetExtendedTcpTable | 5 seconds |
| Auth | Security Event Log (4624/4625/4634/4672) | 3 seconds |

## AI/ML Configuration

### IsolationForest Training

Parameters in `ai/training/isolation_forest.py`:

| Parameter | Default | Description |
|---|---|---|
| `n_estimators` | 100 | Number of isolation trees |
| `contamination` | 0.05 | Expected proportion of anomalies (5%) |
| `max_samples` | 256 | Samples per tree |
| `random_state` | 42 | Reproducibility seed |

### Feature Extraction

17 behavioral features per time window:

**Process:** unique process count, new process rate, suspicious name ratio
**Network:** unique remote IPs, total connections, non-standard port ratio, bytes ratio
**File:** file events, modification rate, sensitive path access count
**Auth:** login attempts, failure ratio, unique source IPs
**Temporal:** event rate variance, burst detection, off-hours activity ratio

### Drift Detection

| Parameter | Default | Description |
|---|---|---|
| `z_threshold` | 3.0 | Standard deviations for drift alert |
| `window_size` | 60 | Seconds per feature window |
| `baseline_path` | `~/.local/share/os-defender/baseline.json` | Baseline profile location |

### Ollama LLM (Optional)

When Ollama is running locally, the AI layer uses it for natural language alert explanations.

| Parameter | Default | Description |
|---|---|---|
| `ollama_url` | `http://localhost:11434` | Ollama API endpoint |
| `model` | `llama3.2` | Model to use |
| `timeout` | 30s | Request timeout |

Falls back to rule-based explanations when Ollama is unavailable.

## Storage

### SQLite Database

Location: `~/.local/share/os-defender/events.db`

WAL mode enabled for concurrent read/write performance.

Tables:
- `events` — normalized security events
- `alerts` — detection alerts with MITRE mapping
- `incidents` — correlated incident groups
- `audit_log` — hash-chained enforcement audit trail

### Quarantine Directory

Location: `~/.local/share/os-defender/quarantine/`

Quarantined files are moved here with SHA-256 integrity verification. Restore verifies the hash matches before returning the file.

## Desktop Application

### Tauri Configuration

In `desktop/src-tauri/tauri.conf.json`:

| Setting | Value |
|---|---|
| Window size | 1200 x 800 |
| Theme | Dark |
| Dev server | `http://localhost:5173` |
| Capabilities | `core:default`, `shell:allow-open` |

### Polling Intervals

| View | Interval | Data |
|---|---|---|
| Dashboard | 5s | Status, events, alerts, health |
| Alerts | 5s | Alert list |
| Process Explorer | 3s | Process events |
| Network Monitor | 5s | Network connections |
| System Health | 10s | Sensor status |
| Other views | On-demand | Manual refresh |

## Security Posture Checks

10 automated hardening checks:

1. `/etc/shadow` permissions (should be 0640 or stricter)
2. SSH root login disabled
3. SSH password authentication disabled
4. Firewall active (nftables/iptables)
5. No world-writable SUID binaries
6. `/tmp` mounted with noexec
7. Core dumps disabled
8. ASLR enabled (`/proc/sys/kernel/randomize_va_space` = 2)
9. Automatic security updates configured
10. No users with empty passwords

## Tamper Protection

### Integrity Manifest

The manifest records SHA-256 hashes of protected files. Verification compares current hashes against the manifest and reports:
- Intact files (hash matches)
- Tampered files (hash mismatch)
- Missing files (deleted since manifest creation)

### Signed Configuration

Configuration files are protected with a SHA-256 hash. The agent verifies this hash at startup and reports violations.
