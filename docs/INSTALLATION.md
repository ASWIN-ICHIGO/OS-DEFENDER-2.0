# OS-DEFENDER 2.0 — Installation Guide

## Prerequisites

| Component | Version | Purpose |
|---|---|---|
| Rust | 1.78+ (edition 2024) | Core engine, agent, CLI |
| Python | 3.11+ | AI/ML layer |
| SQLite | 3.35+ (bundled via rusqlite) | Event storage |
| Node.js | 20+ | Desktop application (optional) |
| npm | 10+ | Desktop frontend build (optional) |

### Arch Linux

```bash
sudo pacman -S rust python python-pip sqlite nodejs npm
```

### Ubuntu / Debian

```bash
sudo apt install build-essential curl pkg-config libssl-dev libsqlite3-dev python3 python3-venv nodejs npm
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Fedora

```bash
sudo dnf install gcc openssl-devel sqlite-devel python3 python3-pip nodejs npm
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/ASWIN-ICHIGO/os-defender-2.0.git
cd os-defender-2.0
```

### 2. Build the Rust Workspace

```bash
cargo build --release
```

This produces three binaries in `target/release/`:
- `os-defender-agent` — background daemon
- `os-defender-cli` — command-line interface

### 3. Install the Binaries

```bash
install -Dm755 target/release/os-defender-agent ~/.cargo/bin/os-defender-agent
install -Dm755 target/release/os-defender-cli   ~/.cargo/bin/os-defender-cli
```

Or use `cargo install`:

```bash
cargo install --path crates/os-defender-agent
cargo install --path crates/os-defender-cli
```

### 4. Create Data Directories

```bash
mkdir -p ~/.local/share/os-defender
```

The agent stores its database, quarantine files, and socket in this directory.

## Agent Setup

### systemd User Service

Copy the provided service file and enable it:

```bash
mkdir -p ~/.config/systemd/user
cp config/os-defender-agent.service ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable os-defender-agent
systemctl --user start os-defender-agent
```

Check status:

```bash
systemctl --user status os-defender-agent
```

The agent listens on `~/.local/share/os-defender/agent.sock` by default.

### Manual Startup

```bash
RUST_LOG=info os-defender-agent
```

## CLI Usage

With the agent running:

```bash
os-defender-cli status          # Agent status
os-defender-cli events          # Recent events
os-defender-cli alerts          # Recent alerts
os-defender-cli health          # System health / blind spots
os-defender-cli audit           # Audit log
os-defender-cli audit verify    # Verify audit chain integrity
os-defender-cli policy get      # Current policy mode
os-defender-cli policy set approve   # Set policy mode
os-defender-cli ai-status       # AI engine status
os-defender-cli hunt            # Threat hunting query
os-defender-cli posture         # Security posture assessment
os-defender-cli persistence     # Persistence mechanism scan
os-defender-cli integrity       # Tamper protection check
```

## AI/ML Layer Setup

### 1. Create Virtual Environment

```bash
cd ai
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -e ".[dev]"
```

For local LLM support (optional):

```bash
pip install -e ".[llm]"
```

### 3. Train the IsolationForest Model

```bash
python -m training.isolation_forest
```

This produces an ONNX model at `~/.local/share/os-defender/model.onnx`.

### 4. Build Baseline Profile

```bash
python -m training.baseline
```

The baseline is used for z-score drift detection.

### 5. Run AI Tests

```bash
pytest
ruff check .
```

## Desktop Application (Optional)

### 1. Install Tauri CLI

```bash
cargo install tauri-cli
```

### 2. Install Frontend Dependencies

```bash
cd desktop
npm install
```

### 3. Development Mode

```bash
cargo tauri dev
```

This starts the Vite dev server and the Tauri window. The agent must be running for IPC to work.

### 4. Production Build

```bash
cargo tauri build
```

Produces platform-specific installers:
- **Linux**: `.deb` and `.AppImage` in `desktop/src-tauri/target/release/bundle/`
- **Windows**: `.msi` installer (requires Windows build environment)

## Quick Start

```bash
# Build everything
cargo build --release

# Create data directory
mkdir -p ~/.local/share/os-defender

# Start the agent (foreground for testing)
RUST_LOG=info ./target/release/os-defender-agent &

# Check it works
./target/release/os-defender-cli status

# View real-time events
./target/release/os-defender-cli events

# Run security posture check
./target/release/os-defender-cli posture

# Stop the agent
./target/release/os-defender-cli shutdown
```

## Verification

After installation, verify the build:

```bash
cargo test                 # 173 tests (unit + integration + performance)
cargo clippy               # Zero warnings
cd ai && pytest            # 41 Python tests
cd ai && ruff check .      # Zero lint issues
```

## Uninstalling

```bash
systemctl --user stop os-defender-agent
systemctl --user disable os-defender-agent
rm ~/.config/systemd/user/os-defender-agent.service
rm ~/.cargo/bin/os-defender-agent
rm ~/.cargo/bin/os-defender-cli
rm -rf ~/.local/share/os-defender
```
