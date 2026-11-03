# OS-DEFENDER 2.0 — Architecture

## Overview

OS-DEFENDER 2.0 is a cross-platform endpoint detection, prevention and response (EDR) application with offline-first AI capabilities.

```
┌─────────────────────────────────────────────────────────┐
│                  Desktop Application                     │
│              (Tauri + React + TypeScript)                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │ Command  │ │ Process  │ │ Network  │ │  Threat    │ │
│  │ Center   │ │ Explorer │ │ Intel    │ │  Hunting   │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘ │
└──────────────────────┬──────────────────────────────────┘
                       │ Authenticated IPC
                       │ (Unix Domain Socket / Named Pipe)
┌──────────────────────┴──────────────────────────────────┐
│                   Security Agent                         │
│               (Rust Background Service)                  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Detection Engine                     │   │
│  │  ┌────────┐  ┌──────────┐  ┌─────────────────┐  │   │
│  │  │ Rules  │  │ Anomaly  │  │  Correlation    │  │   │
│  │  │ Engine │  │ Detector │  │  (Graph-based)  │  │   │
│  │  └────────┘  └──────────┘  └─────────────────┘  │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Platform Collectors                   │   │
│  │  ┌─────────┐ ┌───────┐ ┌─────────┐ ┌──────┐     │   │
│  │  │ Process │ │ File  │ │ Network │ │ Auth │     │   │
│  │  │ /proc   │ │inotify│ │/proc/net│ │journa│     │   │
│  │  └─────────┘ └───────┘ └─────────┘ └──────┘     │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ Response │ │ Health   │ │ Storage  │ │ Audit    │   │
│  │ Engine   │ │ Monitor  │ │ (SQLite) │ │ Log      │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└─────────────────────────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│              AI Intelligence Engine                      │
│                    (Python)                               │
│  ┌──────────┐  ┌───────────┐  ┌─────────────────────┐  │
│  │ Feature  │  │ ONNX      │  │ Local LLM           │  │
│  │ Extract  │  │ Inference │  │ (optional, Ollama)   │  │
│  └──────────┘  └───────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Rust Security Core (`crates/os-defender-core`)

The security engine that runs as a background service independent of the GUI.

- **Event Schema**: Normalized event format with Pydantic-equivalent Serde validation
- **Platform Layer**: Trait-based abstraction — Linux and Windows implement the same interfaces
- **Detection Engine**: Transparent rules + anomaly scoring
- **Correlation**: Graph-based incident grouping (Phase 5)
- **Response Engine**: Policy-driven, dry-run default, human-reviewed (Phase 3)
- **Storage**: SQLite with WAL mode for concurrent read/write
- **Health Monitor**: Blind-spot detector tracking sensor liveness and gaps
- **IPC**: Unix domain socket (Linux) / named pipe (Windows) with JSON-line protocol

### 2. Agent Daemon (`crates/os-defender-agent`)

The background service binary. Runs independently of the desktop app.

- Signal handling for graceful shutdown
- Periodic collector polling
- Event → detection → correlation → response pipeline
- IPC server for CLI and desktop app communication

### 3. CLI (`crates/os-defender-cli`)

Command-line interface for agent management.

- `os-defender status` — agent health and statistics
- `os-defender events` — recent security events
- `os-defender health` — sensor visibility assessment
- `os-defender shutdown` — graceful agent stop

### 4. AI Intelligence Engine (`ai/`)

Python layer for ML and optional LLM capabilities.

- **IsolationForest** anomaly detection with explainable factors
- **Behavioural baselines** per process, network pattern, and file activity
- **ONNX Runtime** for portable, offline inference
- **Local LLM** (optional) via Ollama/llama.cpp for incident explanation
- Communicates with the Rust agent via IPC

### 5. Desktop Application (Phase 8)

Tauri + React + TypeScript professional interface.

- Authenticated IPC connection to agent
- 22 navigation sections from Command Center to Settings
- Dark graphite theme with security-appropriate color coding
- No fake data — all visualizations from the real security engine
- Works offline — no internet required

## Linux Platform Integration

| Subsystem | Source | Mechanism |
|---|---|---|
| Process monitoring | `/proc/PID/{stat,cmdline,exe,status}` | Poll + diff |
| File monitoring | inotify | Event-driven |
| Network monitoring | `/proc/net/{tcp,tcp6,udp,udp6}` | Poll + diff |
| Auth monitoring | `journalctl --follow --output=json` | Stream |
| Network enforcement | nftables (Phase 3) | Rule injection |
| File enforcement | fanotify (Phase 3) | Permission decisions |

## Windows Platform Integration (Phase 4-5)

| Subsystem | Source | Mechanism |
|---|---|---|
| Process monitoring | ETW + NtQuerySystemInformation | Event-driven |
| File monitoring | ReadDirectoryChangesW / ETW | Event-driven |
| Network monitoring | ETW + GetExtendedTcpTable | Event-driven |
| Auth monitoring | Windows Event Log (Security) | Poll |
| Network enforcement | WFP (Windows Filtering Platform) | Callout driver |

## Security Properties

- Agent runs as background service — protection continues without GUI
- Dry-run default for all response actions
- Hash-chained audit log for tamper detection
- Authenticated IPC — GUI cannot bypass policy
- Least-privilege: collectors read-only, enforcement in separate privileged paths
- All AI outputs treated as advisory — deterministic policy engine authorizes enforcement
