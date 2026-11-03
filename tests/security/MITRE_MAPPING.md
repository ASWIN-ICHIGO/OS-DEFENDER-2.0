# MITRE ATT&CK Technique Mapping — OS Defender 2.0

## Coverage Summary

| Tactic | Techniques Covered |
|---|---|
| Credential Access | T1110 |
| Execution | T1059, T1059.004 |
| Impact | T1565.001, T1486 |
| Command and Control | T1071, T1571 |
| Persistence | T1053.003, T1543.002, T1546.004, T1574.006, T1098.004, T1547.001 |

**Total techniques mapped: 13**

---

## T1110 — Brute Force

| Field | Value |
|---|---|
| Detection Rule | R001 (brute-force detection) |
| Detection Method | Counts failed authentication events per source IP within a sliding time window. Fires when threshold is exceeded. Cooldown prevents repeated alerts for the same source. |
| Prevention Action | `BlockIp` — nftables rule (Linux) or WFP/netsh advfirewall rule (Windows) blocking inbound+outbound from source IP |
| Tested | ✅ Unit tests: brute-force rule fires, cooldown works, cross-platform event parity. Enforcement tests: dry-run/approve/execute policy modes. |

## T1059 — Command and Scripting Interpreter

| Field | Value |
|---|---|
| Detection Rule | R002 (suspicious process execution) |
| Detection Method | Pattern matching on process name, executable path, and command-line arguments. Detects reverse shells, crypto miners, reconnaissance tools (whoami, id, uname chains), and suspicious interpreters. |
| Prevention Action | `FreezeProcess` — cgroup v2 freeze (Linux) or Job Object + SuspendThread (Windows) |
| Tested | ✅ Unit tests: suspicious process rule fires on known patterns. Cross-platform event parity tests confirm Windows events trigger same rules. |

## T1059.004 — Unix Shell

| Field | Value |
|---|---|
| Detection Rule | R002 (suspicious process execution) |
| Detection Method | Specific patterns for bash/sh reverse shells (`/dev/tcp`, `nc -e`, `bash -i`), encoded commands, and suspicious shell invocations. |
| Prevention Action | `FreezeProcess` — cgroup v2 freeze (Linux) |
| Tested | ✅ Unit tests: reverse shell pattern detection. Process tree tracking with parent-child analysis and cycle protection. |

## T1565.001 — Stored Data Manipulation

| Field | Value |
|---|---|
| Detection Rule | R003 (sensitive file tampering) |
| Detection Method | inotify (Linux) / FindFirstChangeNotification (Windows) monitoring of sensitive paths: `/etc/shadow`, `/etc/sudoers`, `authorized_keys`, `ld.so.preload`, SSH configs. Fires on create/modify/delete/permission changes. |
| Prevention Action | `QuarantineFile` — move to quarantine directory with SHA-256 integrity verification, restorable |
| Tested | ✅ Unit tests: file tampering rule fires on sensitive path modifications. Quarantine round-trip test (quarantine + restore with integrity check). |

## T1486 — Data Encrypted for Impact (Ransomware)

| Field | Value |
|---|---|
| Detection Rule | R006 (ransomware defense) |
| Detection Method | Multi-signal approach: (1) Canary file monitoring — sentinel files in watched directories detect unauthorized access/deletion. (2) Shannon entropy analysis — identifies encrypted writes above 7.5 bits/byte threshold. (3) Rapid modification tracking — aggregates file modifications within 60-second windows. (4) Rename storm detection — >10 renames in 60 seconds. (5) Known extension matching — 20+ ransomware extensions (.encrypted, .locked, .crypted, .wncry, etc.). |
| Prevention Action | `QuarantineFile` — isolate suspected encrypted files |
| Tested | ✅ Unit tests: canary deployment/verification, canary deletion detection, entropy calculation, rapid modification aggregation, rapid rename detection, known extension matching. |

## T1071 — Application Layer Protocol

| Field | Value |
|---|---|
| Detection Rule | R004 (anomalous network activity) |
| Detection Method | Monitors outbound connections for non-standard ports. Parses `/proc/net/tcp` (Linux) or `GetExtendedTcpTable` (Windows). Flags connections to uncommon ports that deviate from expected HTTP/HTTPS/DNS/SSH traffic. |
| Prevention Action | `BlockIp` — nftables (Linux) or WFP/netsh (Windows) |
| Tested | ✅ Unit tests: detects uncommon outbound port, ignores common ports, ignores private IPs. Cross-platform parity tests. |

## T1571 — Non-Standard Port

| Field | Value |
|---|---|
| Detection Rule | R004 (anomalous network activity) |
| Detection Method | Detects connections on known backdoor ports (4444, 5555, 6666, 8888, 31337, etc.) and flags non-standard service ports. |
| Prevention Action | `BlockIp` — block remote IP at firewall level |
| Tested | ✅ Unit tests: backdoor port detection. |

## T1053.003 — Scheduled Task/Job: Cron

| Field | Value |
|---|---|
| Detection Rule | R005 (persistence mechanism change) |
| Detection Method | Monitors cron directories (`/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/`) via inotify for new or modified cron jobs. Persistence scanner enumerates existing cron entries with risk classification. |
| Prevention Action | Alert + policy engine evaluation. No automatic file quarantine for cron files (too risky). |
| Tested | ✅ Unit tests: persistence change rule fires. Persistence scanner Linux cron enumeration test. |

## T1543.002 — Create or Modify System Process: Systemd Service

| Field | Value |
|---|---|
| Detection Rule | R005 (persistence mechanism change) |
| Detection Method | Monitors systemd unit directories (`/etc/systemd/system/`, `/usr/lib/systemd/system/`, user service dirs) for new or modified service/timer files. Persistence scanner enumerates all systemd services and timers, classifying known vs suspicious. |
| Prevention Action | Alert + policy engine evaluation |
| Tested | ✅ Unit tests: persistence change rule fires on systemd paths. Persistence scanner detects known services. |

## T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification

| Field | Value |
|---|---|
| Detection Rule | R005 (persistence mechanism change) |
| Detection Method | Monitors shell RC files (`.bashrc`, `.bash_profile`, `.profile`, `.zshrc`) for modifications. |
| Prevention Action | Alert + policy engine evaluation |
| Tested | ✅ Unit tests: persistence change rule fires on shell RC file modifications. |

## T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking

| Field | Value |
|---|---|
| Detection Rule | R003 (sensitive file tampering) + R005 (persistence mechanism change) |
| Detection Method | Monitors `/etc/ld.so.preload` and `/etc/ld.so.conf.d/` for modifications that could inject shared libraries into all processes. |
| Prevention Action | `QuarantineFile` — quarantine the modified linker config |
| Tested | ✅ Unit tests: file tampering rule fires on `ld.so.preload`. |

## T1098.004 — Account Manipulation: SSH Authorized Keys

| Field | Value |
|---|---|
| Detection Rule | R003 (sensitive file tampering) + R005 (persistence mechanism change) |
| Detection Method | Monitors `~/.ssh/authorized_keys` and SSH config files (`/etc/ssh/sshd_config`) for unauthorized additions or modifications. |
| Prevention Action | `QuarantineFile` — quarantine unauthorized key file changes |
| Tested | ✅ Unit tests: file tampering rule fires on authorized_keys modification. |

## T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

| Field | Value |
|---|---|
| Detection Rule | R005 (persistence mechanism change) |
| Detection Method | Windows persistence scanner checks Registry Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM` equivalent), startup folder contents, and scheduled tasks. Linux equivalents: XDG autostart, init.d scripts. |
| Prevention Action | Alert + policy engine evaluation |
| Tested | ✅ Unit tests: persistence scanner serialization. Windows-specific scanner is cfg-gated, untested on real Windows. |

---

## Detection-to-Prevention Pipeline

```
Event → Collector → NormalizedEvent → Detection Engine → Alert
  → Policy Engine (suggest_actions) → ResponseAction
  → PolicyMode evaluation (dry_run / approve / execute)
  → Enforcer (nftables/WFP, cgroup/JobObject, quarantine)
  → AuditLog (hash-chained, tamper-evident)
```

## Gaps and Future Work

- No coverage for: T1055 (Process Injection), T1021 (Remote Services), T1003 (OS Credential Dumping), T1070 (Indicator Removal)
- Windows persistence scanner untested on real Windows hardware
- fanotify (file access control decisions) deferred — requires CAP_SYS_ADMIN
- No memory-based detection (e.g., shellcode patterns, ROP chains)
- No network payload inspection (DPI) — only connection metadata
