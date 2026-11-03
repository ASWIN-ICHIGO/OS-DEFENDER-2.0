# Threat Model — OS Defender 2.0

## 1. Assets Protected

| Asset | Protection Method |
|---|---|
| Endpoint file system | File monitoring (inotify/FNCN), tampering detection, quarantine, ransomware defense |
| Running processes | Process collection, suspicious execution detection, process freeze/kill |
| Network connections | Connection monitoring, anomalous port/IP detection, IP blocking |
| User credentials/sessions | Auth event monitoring, brute-force detection, SSH key change alerts |
| Persistence mechanisms | Persistence scanner, change monitoring for systemd/cron/rc/registry |
| System configuration | Security posture checks, tamper protection (integrity manifests) |
| OS Defender itself | Hash-chained audit log, signed config, integrity manifest verification |

## 2. Threat Actors

### Script Kiddies / Opportunistic Attackers

- **Capability:** Known tools, public exploits, automated scanners
- **Relevant techniques:** T1110 (brute force), T1059 (reverse shells), T1486 (commodity ransomware)
- **Detection coverage:** Strong — R001 brute-force, R002 suspicious process patterns match common tools (nc, ncat, socat, crypto miners), R006 ransomware extensions
- **Prevention coverage:** IP blocking for brute force, process freeze for shells, file quarantine for ransomware

### Insider Threats

- **Capability:** Legitimate access, knowledge of internal systems
- **Relevant techniques:** T1098.004 (SSH key manipulation), T1565.001 (data tampering), T1053.003 (cron persistence)
- **Detection coverage:** Moderate — file tampering on sensitive configs, persistence mechanism changes, auth event monitoring
- **Prevention coverage:** Alert-driven (approve mode) — automatic quarantine of sensitive file changes, audit trail for forensics
- **Limitation:** Cannot distinguish authorized admin changes from malicious ones without additional context

### Advanced Persistent Threats (APTs)

- **Capability:** Custom tooling, living-off-the-land, patience
- **Relevant techniques:** T1574.006 (ld.so.preload hijacking), T1546.004 (shell config modification), T1071 (C2 over standard protocols)
- **Detection coverage:** Partial — detects known suspicious patterns but may miss novel tooling. AI anomaly scoring helps with behavioral deviations. Persistence scanner enumerates known mechanisms.
- **Prevention coverage:** Limited — dry-run mode appropriate since false positives are costlier than missed detections at this sophistication level
- **Limitation:** No memory analysis, no DPI, no behavioral sandboxing. Sophisticated evasion (e.g., direct syscalls bypassing proc, fileless malware) not covered.

### Ransomware Operators

- **Capability:** File encryption, data exfiltration, lateral movement
- **Relevant techniques:** T1486 (encryption for impact), T1059 (execution), T1071/T1571 (C2 and exfil)
- **Detection coverage:** Strong — multi-signal ransomware defense (canary files, entropy, rapid modifications, rename storms, known extensions), network anomaly detection
- **Prevention coverage:** File quarantine for suspected encrypted files, IP blocking for C2 connections
- **Limitation:** Cannot prevent encryption already in progress — detection must be fast enough to trigger containment before significant damage

## 3. Attack Surfaces

### Network

| Detection | Prevention |
|---|---|
| R004: anomalous outbound ports, backdoor ports, non-standard connections | `BlockIp`: nftables (Linux) / WFP (Windows) |
| Connection metadata: protocol, direction, local/remote addr/port, state, process | Rollback: unblock with token |
| **Gap:** No payload inspection, no DNS query analysis, no TLS certificate validation | **Gap:** No rate limiting, no connection-level blocking (only IP-level) |

### File System

| Detection | Prevention |
|---|---|
| R003: sensitive file tampering (shadow, sudoers, authorized_keys, ld.so.preload, SSH) | `QuarantineFile`: move + SHA-256, restorable |
| R006: ransomware (canary, entropy, rapid-mod, rename, extensions) | File intelligence: known-good/known-bad reputation DB |
| Integrity manifest: SHA-256 verification of protected files | **Gap:** No fanotify access control (deferred — requires CAP_SYS_ADMIN) |
| **Gap:** No monitoring of /proc/*/mem, no in-memory file detection | |

### Processes

| Detection | Prevention |
|---|---|
| R002: suspicious execution patterns (reverse shells, crypto miners, recon tools) | `FreezeProcess`: cgroup v2 (Linux) / Job Object (Windows) |
| Process tree tracking: parent-child with cycle protection | `KillProcess`: terminate confirmed malicious |
| **Gap:** No process injection detection (T1055), no hollowing detection, no memory scanning | **Gap:** No seccomp/AppArmor integration |

### Authentication

| Detection | Prevention |
|---|---|
| R001: brute-force detection (threshold + time window + cooldown) | `BlockIp`: block source of brute-force attempts |
| Auth events: login, logout, failed, escalation, key auth | **Gap:** No account lockout integration, no MFA enforcement |
| Source IP tracking, service/method identification | |
| **Gap:** No Kerberos/NTLM analysis (Windows), no credential stuffing detection beyond threshold | |

### Persistence

| Detection | Prevention |
|---|---|
| R005: persistence mechanism changes (14 monitored paths on Linux) | Alert + policy engine evaluation |
| Persistence scanner: systemd, cron, shell rc, init.d, XDG, udev (Linux); Registry Run, startup, scheduled tasks (Windows) | **Gap:** No automatic removal of unauthorized persistence — too risky |
| Risk classification: known, suspicious, high_risk | |
| **Gap:** No kernel module monitoring, no bootloader integrity, no firmware | |

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│ Untrusted: External Network                     │
│ ┌─────────────────────────────────────────────┐ │
│ │ Semi-trusted: Local Processes               │ │
│ │ ┌─────────────────────────────────────────┐ │ │
│ │ │ Trusted: OS Defender Agent (root/admin) │ │ │
│ │ │ ┌─────────────────────────────────────┐ │ │ │
│ │ │ │ Verified: Audit Log (hash-chained) │ │ │ │
│ │ │ │          Signed Config              │ │ │ │
│ │ │ │          Integrity Manifest         │ │ │ │
│ │ │ └─────────────────────────────────────┘ │ │ │
│ │ └─────────────────────────────────────────┘ │ │
│ │                                             │ │
│ │ ┌─────────────────────────────────────────┐ │ │
│ │ │ Semi-trusted: Desktop UI (user-level)  │ │ │
│ │ │ Communicates via IPC socket             │ │ │
│ │ └─────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

**Key boundaries:**
- Agent runs as root/admin; desktop UI runs as user — IPC socket is the boundary
- Agent trusts OS kernel APIs (/proc, inotify, journalctl, ToolHelp32, Event Log)
- Agent does NOT trust: file contents, process names, network metadata (all are inspected, not assumed safe)
- Audit log chain is self-verifying — tampering detectable via SHA-256 chain breaks
- AI model is loaded from local disk — no remote model fetching
- Ollama LLM is optional and local-only — no data leaves the endpoint

## 5. Known Limitations and Gaps

### Detection Gaps
- No process injection detection (T1055)
- No memory scanning or fileless malware detection
- No DPI / network payload analysis
- No DNS query monitoring
- No kernel module/rootkit detection
- No container/VM escape detection
- AI model requires training data to establish baseline — cold start has no anomaly detection

### Prevention Gaps
- No seccomp/AppArmor/SELinux integration
- No account lockout enforcement
- No fanotify file access blocking (requires CAP_SYS_ADMIN, deferred)
- No automatic persistence removal (intentional — too destructive)
- IP blocking is binary (block/unblock) — no rate limiting or connection-level control

### Operational Gaps
- Windows collectors and enforcers are cfg-gated, not tested on real Windows
- IPC socket has no authentication — any local process can connect (relies on file permissions)
- No encrypted IPC communication
- Security posture checks are Linux-only
- AI sidecar not yet wired into agent main loop for real-time scoring
- No central management / multi-endpoint coordination

### Evasion Risks
- Process monitoring via /proc polling has a 2-second gap — short-lived processes may be missed
- File monitoring via inotify has event queue limits — burst of events may overflow
- Detection rules use static patterns — novel tool names or obfuscated commands may evade
- Network monitoring parses connection tables — raw socket or kernel-bypass traffic not visible
