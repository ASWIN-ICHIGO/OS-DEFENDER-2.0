# OS-DEFENDER 2.0

**Offline-First AI-Powered Cross-Platform Real-Time Endpoint Detection, Prevention and Automated Response Platform**

## What This Is

A genuine endpoint protection application that monitors OS activity, identifies suspicious behaviour, prevents supported attacks, and responds using locally executed AI and deterministic security policies.

**This is not a website, dashboard mockup, or monitoring-only tool.** It implements real OS-level integrations with actual detection and prevention capabilities.

## Supported Platforms

- **Linux** (primary: EndeavourOS/Arch Linux)
- **Windows 10/11** (second platform)

## Architecture

```
Desktop App (Tauri + React)
        ↕ IPC
Security Agent (Rust daemon)
  ├── Process collector (/proc, ETW)
  ├── File collector (inotify, ReadDirectoryChangesW)
  ├── Network collector (/proc/net, ETW)
  ├── Auth collector (journalctl, Event Log)
  ├── Detection engine (rules + anomaly)
  ├── Response engine (policy-driven, dry-run default)
  └── Storage (SQLite)
        ↕ IPC
AI Engine (Python, ONNX, optional LLM)
```

## Quick Start

### Prerequisites

```bash
# EndeavourOS / Arch Linux
sudo pacman -S rustup nodejs-lts-jod npm
rustup default stable
```

### Build

```bash
cargo build --release
```

### Run the Agent

```bash
# Start the background protection agent
cargo run --bin os-defender-agent

# In another terminal — check status
cargo run --bin os-defender -- status

# View recent events
cargo run --bin os-defender -- events --limit 10

# Check sensor health
cargo run --bin os-defender -- health
```

### Install as systemd Service

```bash
mkdir -p ~/.config/systemd/user
cp config/os-defender-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now os-defender-agent
```

### Run Tests

```bash
# Rust — 173 tests (unit, attack simulation, performance, cross-platform)
cargo test

# Python AI — 41 tests (features, training, inference, baseline, offline)
cd ai && python -m pytest tests/

# Linting
cargo clippy --workspace
cd ai && ruff check .
```

## Project Structure

```
OS-DEFENDER-2.0/
├── crates/
│   ├── os-defender-core/     # Security engine library
│   │   └── src/
│   │       ├── events/       # Normalized event schema
│   │       ├── platform/     # OS-specific collectors
│   │       │   ├── linux/    # /proc, inotify, journalctl
│   │       │   └── windows/  # ETW, Event Log, WFP
│   │       ├── detection/    # Rules + anomaly engine
│   │       ├── correlation/  # Graph-based incident grouping
│   │       ├── response/     # Policy-driven enforcement
│   │       ├── storage/      # SQLite persistence
│   │       ├── health/       # Blind-spot detector
│   │       └── ipc/          # Agent ↔ CLI/GUI protocol
│   ├── os-defender-agent/    # Background daemon binary
│   └── os-defender-cli/      # Command-line interface
├── ai/                       # Python AI/ML layer (IsolationForest, ONNX, Ollama)
├── desktop/                  # Tauri v2 + React 18 desktop app
├── config/                   # systemd service, policies
├── tests/                    # Integration and security tests
│   └── security/             # MITRE mapping, capability matrix, threat model
├── docs/                     # Installation, configuration, architecture, test report
└── scripts/                  # Build and demo scripts
```

## Detection & Prevention

| Capability | MITRE ATT&CK | Rule |
|---|---|---|
| SSH brute-force detection | T1110 | R001 |
| Suspicious process / reverse shell | T1059, T1059.004 | R002 |
| Sensitive file tampering | T1565.001 | R003 |
| Anomalous network / C2 beaconing | T1071, T1571 | R004 |
| Persistence mechanism changes | T1053.003, T1543.002, T1546.004, T1574.006, T1098.004, T1547.001 | R005 |
| Ransomware defense | T1486 | R006 |

**Advanced modules:** Threat hunting (SQL-backed), security posture assessment (10 checks), digital forensics (timeline + evidence), file intelligence (IOC/reputation), persistence scanner, tamper protection (integrity manifest + signed config).

**AI/ML:** IsolationForest anomaly detection, ONNX Runtime inference, baseline drift detection, anomaly explainer, optional local LLM via Ollama — all fully offline.

## Desktop Application

Tauri v2 + React 18 + TypeScript with 22 navigation sections providing full SOC visibility.

```bash
cd desktop && npm install && npm run tauri dev
```

## Documentation

- [docs/INSTALLATION.md](docs/INSTALLATION.md) — Prerequisites, build, setup guide
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — Agent, policy, rules, AI parameters
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — System design, data flow, IPC protocol
- [docs/TEST_REPORT.md](docs/TEST_REPORT.md) — 214 tests across Rust and Python
- [docs/DEMO_SCENARIOS.md](docs/DEMO_SCENARIOS.md) — 12 guided demo scenarios
- [ROADMAP.md](ROADMAP.md) — Development phases and progress
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) — Feature status matrix
- [THREAT_MODEL.md](THREAT_MODEL.md) — Security analysis and limitations
- [SECURITY.md](SECURITY.md) — Security design principles
- [tests/security/MITRE_MAPPING.md](tests/security/MITRE_MAPPING.md) — 13 MITRE techniques
- [tests/security/CAPABILITY_MATRIX.md](tests/security/CAPABILITY_MATRIX.md) — Linux vs Windows parity

## Core Principles

1. **Real-time protection** — actual OS monitoring, not simulated
2. **Offline-first** — all core protection works without internet
3. **Explainable detection** — every alert explains why it fired
4. **Dry-run by default** — no enforcement without explicit approval
5. **Privacy-first** — all processing local, secrets redacted
6. **Measurable results** — real metrics, never fabricated

## License

MIT
