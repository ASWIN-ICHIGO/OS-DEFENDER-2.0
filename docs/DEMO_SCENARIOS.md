# OS-DEFENDER 2.0 — Demo Scenarios

Guided walkthroughs demonstrating OS Defender's detection and prevention capabilities.
All scenarios are safe and use only simulated events via the CLI.

## Prerequisites

```bash
# Start the agent (dry-run mode by default)
sudo ./target/release/os-defender-agent &

# Verify agent is running
./target/release/os-defender-cli status
```

---

## Scenario 1: Brute-Force SSH Detection (T1110)

**What it demonstrates:** Detection of repeated authentication failures from a single source.

1. The agent monitors auth events via journalctl
2. When 5+ failures occur within 300 seconds from the same IP, rule R001 fires
3. In approve/execute mode, the policy engine suggests blocking the source IP via nftables

**Expected output:**
- Alert: "Brute-force attempt: 5 failed logins from 10.0.0.5"
- MITRE: T1110
- Suggested action: BlockIp 10.0.0.5

---

## Scenario 2: Suspicious Process Detection (T1059)

**What it demonstrates:** Detection of reverse shells, crypto miners, and recon tools.

Processes matched by R002:
- `bash -i >& /dev/tcp/...` (reverse shell)
- `ncat -e /bin/sh ...` (netcat shell)
- `xmrig`, `minerd` (crypto miners)
- `whoami`, `id`, `uname -a`, `cat /etc/passwd` (recon)

**Expected output:**
- Alert: "Suspicious process execution"
- MITRE: T1059, T1059.004
- Suggested action: FreezeProcess (PID)

---

## Scenario 3: Sensitive File Tampering (T1565.001)

**What it demonstrates:** Detection of modifications to critical system files.

Monitored paths:
- `/etc/shadow`, `/etc/sudoers`
- `~/.ssh/authorized_keys`
- `/etc/ld.so.preload`
- SSH configuration files

**Expected output:**
- Alert: "Sensitive file modified: /etc/shadow"
- MITRE: T1565.001
- Suggested action: QuarantineFile

---

## Scenario 4: Ransomware Defense (T1486)

**What it demonstrates:** Multi-layered ransomware detection.

Detection methods:
1. **Canary files** — Sentinel files in monitored directories
2. **Entropy analysis** — Shannon entropy > 7.5 bits/byte indicates encryption
3. **Rapid modifications** — 30+ file changes in 10 seconds
4. **Rename storms** — 15+ renames in 10 seconds
5. **Known extensions** — `.encrypted`, `.locked`, `.WNCRY`, etc.

**Expected output:**
- Alert: "Ransomware indicator: rapid file modifications in /home/user/documents"
- MITRE: T1486
- Suggested action: QuarantineFile

---

## Scenario 5: Persistence Mechanism (T1053.003 / T1543.002)

**What it demonstrates:** Detection of persistence installations.

Monitored mechanisms:
- systemd services and timers
- crontab modifications
- Shell RC files (.bashrc, .profile)
- init.d scripts
- XDG autostart entries
- udev rules

**Expected output:**
- Alert: "Persistence Create: /etc/systemd/system/backdoor.service"
- MITRE: T1543.002
- Suggested action: Alert + investigation

---

## Scenario 6: Network Anomaly Detection (T1571)

**What it demonstrates:** Detection of non-standard outbound connections.

Triggers:
- Outbound traffic on suspicious ports (4444, 5555, 8888, etc.)
- Connections to non-RFC1918 IPs on non-standard ports
- Backdoor port listeners

**Expected output:**
- Alert: "Anomalous outbound connection to 185.220.101.1:4444"
- MITRE: T1571
- Suggested action: BlockIp

---

## Scenario 7: Policy Engine Modes

**What it demonstrates:** The three enforcement modes.

```bash
# Check current mode
./target/release/os-defender-cli policy-mode

# Switch to approve mode (auto-execute critical, queue others)
./target/release/os-defender-cli set-policy-mode approve

# Switch to execute mode (enforce all actions)
./target/release/os-defender-cli set-policy-mode execute

# Return to dry-run (log only)
./target/release/os-defender-cli set-policy-mode dry_run
```

---

## Scenario 8: Audit Chain Verification

**What it demonstrates:** Tamper-proof audit logging with SHA-256 hash chains.

```bash
# View recent audit entries
./target/release/os-defender-cli audit-log

# Verify the hash chain integrity
./target/release/os-defender-cli verify-chain
```

Expected: "Chain valid: N entries verified"

---

## Scenario 9: Security Posture Assessment

**What it demonstrates:** Automated hardening checks.

```bash
./target/release/os-defender-cli posture
```

10 checks:
1. /etc/shadow permissions (0640)
2. SSH root login disabled
3. SSH password auth disabled
4. Firewall active (nftables/iptables)
5. SUID binary audit
6. /tmp noexec mount
7. Core dumps disabled
8. ASLR enabled
9. Auto-updates configured
10. No accounts with empty passwords

---

## Scenario 10: Threat Hunting

**What it demonstrates:** SQL-backed event querying with rich filters.

```bash
# Hunt for all process events
./target/release/os-defender-cli hunt --type process

# Hunt for high-severity events
./target/release/os-defender-cli hunt --severity high

# Hunt for events involving a specific user
./target/release/os-defender-cli hunt --username root

# Hunt for events on a specific file path
./target/release/os-defender-cli hunt --file /etc/shadow
```

---

## Scenario 11: AI Engine Status

**What it demonstrates:** Offline AI/ML anomaly detection status.

```bash
./target/release/os-defender-cli ai-status
```

Shows:
- IsolationForest model loaded/not loaded
- Baseline learning status
- Events scored and anomalies detected
- Drift detection status
- Ollama LLM availability

---

## Scenario 12: Desktop Application

**What it demonstrates:** Full graphical security operations center.

```bash
cd desktop
npm install
npm run tauri dev
```

22 navigation sections provide real-time visibility into all agent capabilities.
