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
cargo test
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
├── ai/                       # Python AI/ML layer
├── desktop/                  # Tauri + React desktop app
├── config/                   # systemd service, policies
├── tests/                    # Integration and security tests
└── docs/                     # Additional documentation
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — System design and component details
- [ROADMAP.md](ROADMAP.md) — Development phases and progress
- [THREAT_MODEL.md](THREAT_MODEL.md) — Security analysis and limitations
- [SECURITY.md](SECURITY.md) — Security design principles
- [TESTING.md](TESTING.md) — Testing strategy
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) — Current feature status

## Core Principles

1. **Real-time protection** — actual OS monitoring, not simulated
2. **Offline-first** — all core protection works without internet
3. **Explainable detection** — every alert explains why it fired
4. **Dry-run by default** — no enforcement without explicit approval
5. **Privacy-first** — all processing local, secrets redacted
6. **Measurable results** — real metrics, never fabricated

## License

MIT
