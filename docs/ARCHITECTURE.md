# OS-DEFENDER 2.0 — Architecture Document

## System Overview

OS-DEFENDER 2.0 is an offline-first, AI-powered endpoint detection, prevention, and response (EDPR) platform. It runs entirely on the local machine with no cloud dependencies.

```
┌─────────────────────────────────────────────────────────┐
│                   Desktop Application                    │
│              (Tauri v2 + React 18 + TypeScript)          │
└──────────────────────────┬──────────────────────────────┘
                           │ IPC (Unix socket / named pipe)
┌──────────────────────────▼──────────────────────────────┐
│                    Security Agent Daemon                  │
│                    (os-defender-agent)                    │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐ │
│  │Collectors│ │ Detection │ │ Response │ │  Storage  │ │
│  │  (OS)    │ │  Engine   │ │  Engine  │ │ (SQLite)  │ │
│  └──────────┘ └───────────┘ └──────────┘ └───────────┘ │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐ │
│  │ Advanced │ │   Health  │ │   IPC    │ │Correlation│ │
│  │ Modules  │ │  Monitor  │ │  Server  │ │  Engine   │ │
│  └──────────┘ └───────────┘ └──────────┘ └───────────┘ │
└─────────────────────────────────────────────────────────┘
                           │ Feature vectors (JSON)
┌──────────────────────────▼──────────────────────────────┐
│                    AI/ML Sidecar                         │
│              (Python + ONNX Runtime)                     │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐ │
│  │ Feature  │ │Isolation  │ │  Drift   │ │  Ollama   │ │
│  │Extractor │ │  Forest   │ │Detection │ │   LLM     │ │
│  └──────────┘ └───────────┘ └──────────┘ └───────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Crate Structure

### `os-defender-core` (Library Crate)

The shared security engine library. All detection, storage, and protocol logic lives here.

```
crates/os-defender-core/src/
├── lib.rs                  # Public module exports
├── events/
│   ├── mod.rs              # Re-exports schema + severity
│   ├── schema.rs           # NormalizedEvent, context types, builder
│   └── severity.rs         # Severity enum (Info → Critical)
├── platform/
│   ├── mod.rs              # Collector traits
│   ├── linux/              # /proc, inotify, journalctl collectors
│   └── windows/            # ToolHelp32, Event Log, WFP collectors
├── detection/
│   ├── mod.rs              # Engine + rule exports
│   ├── engine.rs           # DetectionEngine: process_event(), tick()
│   ├── alert.rs            # Alert struct with MITRE techniques
│   └── rules/
│       ├── mod.rs           # default_ruleset() factory
│       ├── brute_force.rs   # R001: threshold + cooldown
│       ├── suspicious_process.rs  # R002: pattern matching
│       ├── file_tampering.rs      # R003: sensitive paths + rapid mod
│       ├── anomalous_network.rs   # R004: uncommon ports
│       ├── persistence_change.rs  # R005: 14 persistence patterns
│       └── ransomware.rs          # R006: multi-signal ransomware
├── correlation/
│   └── mod.rs              # Event correlation engine
├── response/
│   ├── mod.rs              # Response module exports
│   ├── policy.rs           # PolicyEngine: DryRun/Approve/Execute
│   ├── audit.rs            # Hash-chained audit log
│   └── enforcement/
│       ├── nftables.rs     # Linux: nft CLI wrapper
│       ├── cgroup.rs       # Linux: cgroup v2 freeze/thaw
│       ├── wfp.rs          # Windows: netsh firewall
│       ├── job_object.rs   # Windows: Job Object containment
│       └── quarantine.rs   # Cross-platform file quarantine
├── storage/
│   └── sqlite.rs           # SqliteStore: WAL mode, CRUD operations
├── health/
│   ├── mod.rs              # Health module exports
│   └── blindspot.rs        # Sensor status, visibility assessment
├── ipc/
│   ├── mod.rs              # IPC module exports
│   └── protocol.rs         # IpcRequest/IpcResponse enums, socket paths
└── advanced/
    ├── mod.rs              # Advanced module exports
    ├── ransomware.rs       # Canary files, entropy detection
    ├── persistence.rs      # Persistence mechanism scanner
    ├── file_intel.rs       # SHA-256 reputation, IOC lists
    ├── hunting.rs          # SQL-backed threat hunting queries
    ├── forensics.rs        # Timeline, evidence collection, reports
    ├── posture.rs          # 10 security hardening checks
    └── tamper.rs           # Integrity manifest, signed config
```

### `os-defender-agent` (Binary Crate)

The background daemon. Runs as a systemd user service.

Responsibilities:
- Starts all platform collectors (process, file, network, auth)
- Runs the detection engine on every collected event
- Manages the policy engine and enforcement
- Writes events, alerts, and audit entries to SQLite
- Serves IPC requests from CLI and desktop app
- Monitors sensor health and reports blind spots

### `os-defender-cli` (Binary Crate)

Command-line interface. Connects to the agent via IPC socket.

13 commands mapping to IPC request types.

## Data Flow

### Event Pipeline

```
OS Signals → Collector → NormalizedEvent → DetectionEngine → Alert
                                               │
                                               ▼
                                         PolicyEngine
                                               │
                                    ┌──────────┼──────────┐
                                    ▼          ▼          ▼
                                 DryRun    Approve    Execute
                                 (log)    (queue)    (enforce)
                                               │
                                               ▼
                                          AuditLog
                                     (hash-chained)
```

### Event Schema

Every security event is normalized into `NormalizedEvent`:

```rust
pub struct NormalizedEvent {
    pub event_id: String,          // UUID v4
    pub timestamp: DateTime<Utc>,
    pub endpoint_id: String,       // Machine identifier
    pub os_type: OsType,           // Linux | Windows
    pub event_type: EventType,     // Process | File | Network | Authentication
    pub severity: Severity,        // Info | Low | Medium | High | Critical
    pub process: Option<ProcessContext>,
    pub file: Option<FileContext>,
    pub network: Option<NetworkContext>,
    pub auth: Option<AuthContext>,
    pub collector: Option<String>,
    pub evidence_refs: Vec<String>,
    pub fingerprint: Option<String>,
}
```

Context types carry domain-specific fields (PIDs, file paths, ports, usernames).

### Alert Schema

```rust
pub struct Alert {
    pub alert_id: String,
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub source: DetectionSource,   // Rule | AI | Correlation
    pub rule_id: Option<String>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub confidence: f64,           // 0.0 – 1.0
    pub factors: Vec<Factor>,
    pub mitre_techniques: Vec<String>,
}
```

## IPC Protocol

Communication uses Unix domain sockets (Linux) or named pipes (Windows) with a JSON-line protocol.

### Socket Location

- System: `/run/os-defender/agent.sock`
- User: `~/.local/share/os-defender/agent.sock`

### Request/Response

```
Client → Agent: JSON line (IpcRequest)
Agent → Client: JSON line (IpcResponse)
```

13 request types: `Status`, `GetEvents`, `GetAlerts`, `GetHealth`, `GetAuditLog`, `GetPolicyMode`, `SetPolicyMode`, `VerifyAuditChain`, `GetAiStatus`, `ThreatHunt`, `GetPosture`, `GetPersistence`, `VerifyIntegrity`, `Shutdown`.

## Storage Layer

### SQLite with WAL Mode

WAL (Write-Ahead Logging) enables concurrent reads during writes — critical for an agent that collects events while the desktop app queries them.

Tables:
- `events` — all normalized events (indexed by type, timestamp)
- `alerts` — detection alerts (indexed by severity, timestamp)
- `incidents` — correlated incident groups
- `audit_log` — hash-chained enforcement log

### Audit Chain Integrity

Each audit entry contains:
- `prev_hash` — SHA-256 of the previous entry
- `entry_hash` — SHA-256 of (entry content + prev_hash)

This forms a tamper-evident chain. The `verify_audit_chain` command walks the chain and reports any breaks.

## AI/ML Architecture

### Offline-First Design

All AI inference runs locally:
1. **Training** — scikit-learn IsolationForest on collected event features
2. **Export** — ONNX format via skl2onnx
3. **Inference** — ONNX Runtime (CPU) for real-time scoring
4. **Explanation** — Per-feature z-score decomposition

No cloud APIs, no internet required.

### Feature Pipeline

```
NormalizedEvents → FeatureExtractor → 17-dim vector → IsolationForest → anomaly score
                                           │
                                           ▼
                                    BaselineProfile → DriftDetector → drift alert
                                           │
                                           ▼
                                    AnomalyExplainer → "network traffic anomaly:
                                                        unique_remote_ips +3.2σ"
```

### Optional LLM Integration

When Ollama runs locally, the AI layer queries it for natural-language alert explanations. This is strictly optional — the system falls back to rule-based explanations.

## Platform Abstraction

### Collector Traits

```rust
pub trait ProcessCollector { fn collect(&mut self) -> Vec<NormalizedEvent>; }
pub trait FileCollector    { fn collect(&mut self) -> Vec<NormalizedEvent>; }
pub trait NetworkCollector { fn collect(&mut self) -> Vec<NormalizedEvent>; }
pub trait AuthCollector    { fn collect(&mut self) -> Vec<NormalizedEvent>; }
```

Each trait has Linux and Windows implementations behind `#[cfg(target_os)]`.

### Linux Sources

| Collector | OS Interface |
|---|---|
| Process | `/proc/[pid]/stat`, `/proc/[pid]/cmdline`, `/proc/[pid]/status` |
| File | `inotify_init1`, `inotify_add_watch` |
| Network | `/proc/net/tcp`, `/proc/net/udp`, inode→PID resolution |
| Auth | `journalctl -f -o json` streaming |

### Windows Sources

| Collector | Win32 API |
|---|---|
| Process | `CreateToolhelp32Snapshot`, `Process32First/Next` |
| File | `FindFirstChangeNotificationW` |
| Network | `GetExtendedTcpTable` (IPv4) |
| Auth | `OpenEventLogW` (Security), event IDs 4624/4625/4634/4672 |

## Enforcement Layer

### Linux

| Action | Mechanism | Rollback |
|---|---|---|
| Network block | `nft add rule` (comment-tagged) | `nft delete rule` by handle |
| Process freeze | cgroup v2 `freezer` | Thaw via cgroup write |
| File quarantine | Move to quarantine dir | Restore with SHA-256 verify |

### Windows

| Action | Mechanism | Rollback |
|---|---|---|
| Network block | `netsh advfirewall` rule | `netsh delete rule` by name |
| Process contain | Job Object + `SuspendThread` | `ResumeThread` |
| File quarantine | Move + ACL restriction | Restore with SHA-256 verify |

## Desktop Application

### Technology Stack

- **Backend**: Tauri v2 (Rust), communicates with agent via IPC
- **Frontend**: React 18, TypeScript, Vite
- **Styling**: Custom CSS with 40+ design tokens (dark graphite SOC theme)
- **State**: React hooks with polling-based refresh

### Architecture

```
React Components → invoke() → Tauri Commands → Unix Socket → Agent
     ▲                                                         │
     └──────────── JSON Response ◄─────────────────────────────┘
```

13 Tauri commands mirror the IPC protocol. Each command:
1. Connects to the agent socket
2. Sends an `IpcRequest` JSON line
3. Reads the `IpcResponse`
4. Returns typed data to the React frontend

## Security Properties

1. **No cloud dependency** — all detection and enforcement is local
2. **Dry-run by default** — enforcement requires explicit mode change
3. **Tamper-evident audit** — SHA-256 hash chain on all actions
4. **Least privilege** — systemd hardening (NoNewPrivileges, ProtectSystem, MemoryDenyWriteExecute)
5. **Privacy-first** — no telemetry, no data exfiltration
6. **Explainable** — every alert cites rule ID, MITRE technique, and contributing factors
7. **Offline AI** — ONNX inference with no network calls

## MITRE ATT&CK Coverage

13 techniques across 7 tactics:

| Tactic | Techniques |
|---|---|
| Initial Access | T1110 (Brute Force) |
| Execution | T1059 (Command and Scripting Interpreter), T1059.004 (Unix Shell) |
| Persistence | T1053.003 (Cron), T1543.002 (Systemd Service), T1546.004 (Unix Shell Config), T1547.001 (Registry Run Keys), T1098.004 (SSH Authorized Keys) |
| Defense Evasion | T1574.006 (Dynamic Linker Hijacking) |
| Impact | T1486 (Data Encrypted for Impact), T1565.001 (Stored Data Manipulation) |
| Command and Control | T1071 (Application Layer Protocol), T1571 (Non-Standard Port) |
